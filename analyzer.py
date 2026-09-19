#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRUST404 Track 1 - Smart Contract Threat Detection
오프라인, 규칙 기반 Solidity 정적 분석기.

네트워크 호출 없이, 정규식 + 괄호 매칭 기반의 경량 파서로 컨트랙트의
함수/모디파이어/상태변수를 추출한 뒤, 권한 구조와 로직 흐름을 보는
탐지 규칙(rule) 들을 적용해 MALICIOUS / BENIGN / UNCERTAIN 을 판정한다.

외부 패키지에 의존하지 않는다 (표준 라이브러리만 사용).
"""
import sys
import os
import re
import json
import signal

PER_FILE_TIMEOUT_SEC = int(os.environ.get("TRUST404_PER_FILE_TIMEOUT", "20"))


class _AnalysisTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _AnalysisTimeout()


_HAS_ALARM = hasattr(signal, "SIGALRM")


# --------------------------------------------------------------------------
# 1. 전처리: 주석/문자열을 안전하게 제거하되 줄바꿈은 보존한다.
# --------------------------------------------------------------------------
def strip_comments_and_strings(src: str) -> str:
    out = []
    i = 0
    n = len(src)
    in_line_comment = False
    in_block_comment = False
    in_string = None  # "'" or '"'
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if in_string:
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if c == in_string:
                in_string = None
                out.append(" ")
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        # not inside comment/string
        if c == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
            continue
        if c == '"' or c == "'":
            in_string = c
            out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def line_of(offset: int, newline_offsets) -> int:
    # newline_offsets: 정렬된 '\n' 위치 리스트. 1-based 줄번호 반환.
    lo, hi = 0, len(newline_offsets)
    while lo < hi:
        mid = (lo + hi) // 2
        if newline_offsets[mid] < offset:
            lo = mid + 1
        else:
            hi = mid
    return lo + 1


def find_matching_brace(text: str, open_idx: int) -> int:
    """text[open_idx] == '{' 라고 가정하고 매칭되는 '}' 의 인덱스를 반환."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


# --------------------------------------------------------------------------
# 2. 컨트랙트 / 함수 / 모디파이어 / 상태변수 파싱
# --------------------------------------------------------------------------
CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?contract\s+(\w+)(?:\s+is\s+[^\{]+)?\s*\{"
)
FUNCTION_HEAD_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
CONSTRUCTOR_HEAD_RE = re.compile(r"\bconstructor\s*\(")
MODIFIER_HEAD_RE = re.compile(r"\bmodifier\s+(\w+)\s*\(")
FALLBACK_RECEIVE_RE = re.compile(r"\b(fallback|receive)\s*\(")

STATE_VAR_RE = re.compile(
    r"^\s*((?:mapping\s*\([^;{}]*?\)|address(?:\s+payable)?|u?int\d*|bool|string|bytes\d*)"
    r"(?:\[\])?)\s+((?:public|private|internal|external|constant|immutable|override|payable)\s*)*"
    r"(\w+)\s*(=\s*([^;]+))?;",
    re.MULTILINE,
)


class Func:
    def __init__(self, name, header, body, body_start_idx, header_start_idx):
        self.name = name
        self.header = header  # visibility/modifiers/returns 텍스트
        self.body = body
        self.body_start_idx = body_start_idx
        self.header_start_idx = header_start_idx
        self.modifiers = re.findall(r"\b(\w+)\s*(?:\([^)]*\))?\s*(?=\b(?:public|private|internal|external|view|pure|payable|returns|\{)|$)", header)
        vis = "internal"
        for v in ("external", "public", "internal", "private"):
            if re.search(r"\b" + v + r"\b", header):
                vis = v
                break
        self.visibility = vis
        self.is_payable = bool(re.search(r"\bpayable\b", header))


class Contract:
    def __init__(self, name):
        self.name = name
        self.functions = []      # list[Func]
        self.modifiers = {}      # name -> body text
        self.state_vars = []     # list[(type, name, init)]
        self.constructor = None  # Func or None
        self.raw_body = ""
        self.body_start_idx = 0


def parse_source(stripped: str):
    contracts = []
    for m in CONTRACT_RE.finditer(stripped):
        name = m.group(1)
        open_idx = m.end() - 1
        close_idx = find_matching_brace(stripped, open_idx)
        body = stripped[open_idx + 1:close_idx]
        c = Contract(name)
        c.raw_body = body
        c.body_start_idx = open_idx + 1

        # 상태 변수 (함수/모디파이어 정의를 우선 잘라내지 않고 라인 단위로 매칭 -
        # 함수 시그니처와 겹치지 않도록 세미콜론으로 끝나는 단순 선언만 매칭됨)
        for sv in STATE_VAR_RE.finditer(body):
            typ = sv.group(1).strip()
            varname = sv.group(3)
            init = (sv.group(5) or "").strip()
            c.state_vars.append((typ, varname, init))

        # 모디파이어
        for mm in MODIFIER_HEAD_RE.finditer(body):
            mod_name = mm.group(1)
            paren_open = body.index("(", mm.start())
            paren_close = find_matching_paren(body, paren_open)
            after = body[paren_close + 1:]
            brace_rel = after.find("{")
            if brace_rel == -1:
                continue
            brace_open = paren_close + 1 + brace_rel
            brace_close = find_matching_brace(body, brace_open)
            mod_body = body[brace_open + 1:brace_close]
            c.modifiers[mod_name] = mod_body

        # 함수 (constructor 포함)
        heads = []
        for fm in FUNCTION_HEAD_RE.finditer(body):
            heads.append((fm.group(1), fm.start(), fm.end() - 1))
        for cm in CONSTRUCTOR_HEAD_RE.finditer(body):
            heads.append(("constructor", cm.start(), cm.end() - 1))
        for fbm in FALLBACK_RECEIVE_RE.finditer(body):
            heads.append((fbm.group(1), fbm.start(), fbm.end() - 1))
        heads.sort(key=lambda t: t[1])

        for fname, hstart, paren_open in heads:
            paren_close = find_matching_paren(body, paren_open)
            after = body[paren_close + 1:]
            # 다음 '{' 또는 ';' (abstract/인터페이스 함수는 본문이 없음) 중 먼저 나오는 것을 찾는다
            brace_rel = after.find("{")
            semi_rel = after.find(";")
            if brace_rel == -1:
                continue  # 본문 없는 선언은 스킵 (인터페이스 등)
            if semi_rel != -1 and semi_rel < brace_rel:
                continue
            header_text = body[paren_close + 1: paren_close + 1 + brace_rel]
            brace_open = paren_close + 1 + brace_rel
            brace_close = find_matching_brace(body, brace_open)
            fn_body = body[brace_open + 1:brace_close]
            func = Func(fname, header_text, fn_body, brace_open + 1, hstart)
            if fname == "constructor":
                c.constructor = func
            else:
                c.functions.append(func)

        contracts.append(c)
    return contracts


# --------------------------------------------------------------------------
# 3. 권한 구조 helper
# --------------------------------------------------------------------------
OWNER_NAME_RE = re.compile(r"\b(owner|admin|governor|manager|operator|deployer|dev)\b", re.IGNORECASE)


def owner_like_state_vars(contract: Contract):
    names = []
    for typ, varname, init in contract.state_vars:
        if typ.startswith("address") and OWNER_NAME_RE.search(varname):
            names.append(varname)
    if not names:
        # owner-스러운 변수명이 없어도 msg.sender == X 형태로 쓰이는 address 변수를 폴백으로 채택
        for typ, varname, init in contract.state_vars:
            if typ.startswith("address"):
                names.append(varname)
    return names


def modifier_is_owner_gate(mod_body: str, owner_vars) -> bool:
    if "msg.sender" not in mod_body:
        return False
    for ov in owner_vars:
        if re.search(r"msg\.sender\s*==\s*" + re.escape(ov), mod_body) or \
           re.search(re.escape(ov) + r"\s*==\s*msg\.sender", mod_body):
            return True
    if OWNER_NAME_RE.search(mod_body) and ("==" in mod_body):
        return True
    return False


def function_is_privileged(func: Func, contract: Contract, owner_vars) -> (bool, str):
    """함수가 owner/관리자 전용인지 여부와 근거 문자열을 반환."""
    for mod in func.modifiers:
        mod_body = contract.modifiers.get(mod)
        if mod_body is not None and modifier_is_owner_gate(mod_body, owner_vars):
            return True, "modifier %s" % mod
    # 본문 첫 부분의 인라인 require/if 검사
    head = func.body[:300]
    for ov in owner_vars:
        if re.search(r"require\s*\(\s*msg\.sender\s*==\s*" + re.escape(ov), head) or \
           re.search(r"if\s*\(\s*msg\.sender\s*!=\s*" + re.escape(ov), head):
            return True, "inline msg.sender == %s check" % ov
    return False, ""


def find_line(contract: Contract, local_idx: int, newline_offsets) -> int:
    return line_of(contract.body_start_idx + local_idx, newline_offsets)


# --------------------------------------------------------------------------
# 4. 탐지 규칙 (Detectors)
#    각 함수는 findings 리스트에 dict 를 추가한다:
#    {verdict_hint: "MALICIOUS"|"BENIGN_NOTE", function, line, reason, risk_level, risk_type}
# --------------------------------------------------------------------------
CAP_NAME_RE = re.compile(r"(max[_a-z]*supply|supply[_a-z]*cap|hard[_ ]?cap|\bcap\b|mint[_a-z]*limit|_?cap_?)", re.IGNORECASE)
SUPPLY_INCREASE_RE = re.compile(r"\btotalSupply\s*(\+=|=\s*totalSupply\s*\+)")
BALANCE_INCREASE_RE = re.compile(r"\b(\w+)\s*\[\s*(\w+)\s*\]\s*\+=")


def detect_uncapped_mint(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    if func.name == "constructor":
        return
    body = func.body
    inc_matches = list(SUPPLY_INCREASE_RE.finditer(body))
    if not inc_matches:
        return
    privileged, priv_evidence = function_is_privileged(func, contract, owner_vars)

    # 상한 검사 탐색: totalSupply 증가 이전 구간에서 cap성 변수/식별자와의 비교(require/if)를 찾는다
    first_inc = inc_matches[0]
    first_inc_idx = first_inc.start()
    pre_segment = body[:first_inc_idx]
    capped = False
    cap_evidence = None
    checked_amount_var = None
    cap_var = None
    for cond_m in re.finditer(r"(require|if)\s*\(([^;{]*(?:<=|<)[^;{]*)\)", pre_segment):
        cond = cond_m.group(2)
        if "totalSupply" in cond or "amount" in cond or "supply" in cond.lower():
            if CAP_NAME_RE.search(cond) or re.search(r"<=?\s*\d", cond):
                capped = True
                cap_evidence = cond.strip()
                am_m = re.search(r"totalSupply\s*\+\s*(\w+)", cond)
                if am_m:
                    checked_amount_var = am_m.group(1)
                cap_ids = re.findall(r"<=?\s*([A-Za-z_]\w*)", cond)
                if cap_ids:
                    cap_var = cap_ids[-1]
                break
    line = find_line(contract, func.body_start_idx + first_inc_idx, newline_offsets)

    if capped:
        # (a) 실제 증가량이 검사한 변수와 일치하는지 확인 ("가짜 상한" - 검사와 효과의 불일치)
        rhs_end = body.find(";", first_inc.end())
        rhs_text = body[first_inc.end():rhs_end].strip() if rhs_end != -1 else ""
        rhs_norm = re.sub(r"[\s()]+", "", rhs_text)
        if checked_amount_var and rhs_text and rhs_norm != checked_amount_var:
            out.append({
                "malicious": True,
                "function": func.name,
                "line": line,
                "reason": "%s()는 상한 검사에서 %s 값을 검사하지만, 실제로 totalSupply에 더하는 값은 '%s'로 서로 일치하지 않습니다. 검사는 통과하면서 실제 발행량은 검사되지 않은 만큼 늘어날 수 있어 상한이 무력화됩니다." % (func.name, checked_amount_var, rhs_text),
                "risk_level": "CRITICAL",
                "risk_type": "BACKDOOR",
            })
            return

        # (b) 상한 변수 자체가 소유자가 자유롭게 올릴 수 있는 가변값인지 확인 ("가변 상한" 우회)
        if cap_var and not cap_var.isdigit():
            cap_type = None
            for typ, vn, init in contract.state_vars:
                if vn == cap_var:
                    cap_type = typ
                    break
            is_fixed = cap_type is not None and ("constant" in cap_type or "immutable" in cap_type)
            if cap_type is not None and not is_fixed:
                setter, setter_ev = find_setter_privilege(contract, cap_var, owner_vars)
                if setter is not None:
                    bound_re = re.search(r"(require|if)\s*\([^;{]*(<=|<)[^;{]*\)", setter.body)
                    if bound_re is None:
                        out.append({
                            "malicious": True,
                            "function": func.name,
                            "line": line,
                            "reason": "%s()의 상한(%s)은 상수가 아니라 %s()에서 소유자가 별도 상한 검증 없이 자유롭게 올릴 수 있는 변수입니다. 상한을 먼저 올린 뒤 발행하면 사실상 무제한 발행과 동일합니다." % (func.name, cap_var, setter.name),
                            "risk_level": "CRITICAL",
                            "risk_type": "BACKDOOR",
                        })
                        return
        out.append({
            "malicious": False,
            "function": func.name,
            "line": line,
            "reason": "%s()는 발행 전 공급량 상한을 코드로 강제합니다 (%s). 상한 내 희석은 위험으로 부기하되 verdict는 BENIGN입니다." % (func.name, cap_evidence),
            "risk_level": "LOW",
            "risk_type": "CENTRALIZATION",
        })
        return

    if privileged:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s 로 소유자 전용이며, totalSupply 를 증가시키기 전에 공급량 상한을 검사하지 않습니다. 소유자가 발행량을 무제한으로 늘려 보유자 지분을 희석할 수 있습니다." % (func.name, priv_evidence),
            "risk_level": "CRITICAL",
            "risk_type": "BACKDOOR",
        })
    else:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 호출 권한 제한이 없고 공급량 상한 검사도 없어, 누구나 임의로 totalSupply/잔고를 증가시킬 수 있습니다." % func.name,
            "risk_level": "CRITICAL",
            "risk_type": "VULNERABILITY",
        })


TRANSFER_FUNC_NAMES = {"transfer", "transferFrom", "_transfer", "send"}
GATE_MAPPING_NAME_RE = re.compile(r"(white\s*list|black\s*list|frozen|blocked|banned|blacklisted|whitelisted|allowed|canTransfer|isExcluded)", re.IGNORECASE)
GLOBAL_FLAG_NAME_RE = re.compile(r"^(paused|locked|frozen|tradingEnabled|stopped|halted|enabled)$", re.IGNORECASE)


def find_setter_privilege(contract: Contract, varname: str, owner_vars):
    for f in contract.functions:
        if re.search(r"\b" + re.escape(varname) + r"\s*(\[[^\]]*\])?\s*=", f.body):
            priv, ev = function_is_privileged(f, contract, owner_vars)
            if priv:
                return f, ev
    return None, None


def detect_transfer_asymmetry(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    if func.name not in TRANSFER_FUNC_NAMES:
        return
    body = func.body
    # per-address mapping gate: mapping(address=>bool) 변수를 msg.sender/from 인덱스로 검사
    mapping_gate_names = {n for t, n, i in contract.state_vars if t.startswith("mapping") and GATE_MAPPING_NAME_RE.search(n)}
    global_flag_names = {n for t, n, i in contract.state_vars if (t == "bool") and GLOBAL_FLAG_NAME_RE.search(n)}

    # require(...) / if(...) 의 조건식 전체를 뽑아서 && / || 로 여러 항이 묶인 복합 조건도 인식한다
    seen_lines = set()
    for cm in re.finditer(r"(require|if)\s*\(([^)]*)\)", body):
        cond = cm.group(2)
        line = find_line(contract, func.body_start_idx + cm.start(), newline_offsets)

        for gate_name in mapping_gate_names:
            idx_m = re.search(re.escape(gate_name) + r"\s*\[\s*(msg\.sender|from|sender)\s*\]", cond)
            if not idx_m:
                continue
            setter, setter_ev = find_setter_privilege(contract, gate_name, owner_vars)
            if setter is None:
                continue
            key = (line, gate_name)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            out.append({
                "malicious": True,
                "function": func.name,
                "line": line,
                "reason": "%s()는 %s[%s] 값을 근거로 전송 가능 여부를 결정하며, 이 값은 %s()에서 소유자만 변경할 수 있습니다(%s). 소유자가 임의로 보유자의 전송 가능 여부를 결정하는 비대칭 구조입니다." % (func.name, gate_name, idx_m.group(1), setter.name, setter_ev),
                "risk_level": "CRITICAL",
                "risk_type": "BACKDOOR",
            })

        for flag_name in global_flag_names:
            if not re.search(r"\b" + re.escape(flag_name) + r"\b", cond):
                continue
            if re.search(re.escape(flag_name) + r"\s*\[", cond):
                continue  # 매핑 변수와 이름이 겹치는 경우 방지
            exempts_owner = False
            for ov in owner_vars:
                if re.search(r"msg\.sender\s*(==|!=)\s*" + re.escape(ov) + r"\b", cond):
                    exempts_owner = True
                    break
            key = (line, flag_name)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            if exempts_owner:
                out.append({
                    "malicious": True,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()의 전송 제한(%s)이 소유자에게는 예외적으로 적용되지 않아, 소유자만 팔 수 있고 일반 보유자는 팔 수 없는 비대칭 구조입니다." % (func.name, flag_name),
                    "risk_level": "CRITICAL",
                    "risk_type": "BACKDOOR",
                })
            else:
                out.append({
                    "malicious": False,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()의 전송 제한(%s)은 소유자를 포함해 모든 주소에 동일하게 적용되는 대칭적 가용성 제약이므로 자산이 남의 손으로 넘어가는 경로가 아닙니다. 다만 소유자가 이 플래그를 제어한다면 중앙화 위험으로 부기합니다." % (func.name, flag_name),
                    "risk_level": "LOW",
                    "risk_type": "CENTRALIZATION",
                })


def detect_owner_exemption(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    """함수 이름/변수 이름에 의존하지 않고, '소유자만 예외' 패턴 자체를 코드 구조로 잡는다.
    예: if (msg.sender != owner) { require(...); ... }  또는 require(cond || msg.sender == owner)
    다른 사람에게는 적용되는 검사/차감을 소유자만 비켜가는 함수는 그 자체로 비대칭 권한이다."""
    if func.name in ("constructor",):
        return
    body = func.body
    exempt = None  # (owner_var, position)

    for m in re.finditer(r"if\s*\(([^)]*)\)", body):
        cond = m.group(1)
        for ov in owner_vars:
            if re.search(r"msg\.sender\s*!=\s*" + re.escape(ov) + r"\b", cond):
                exempt = (ov, m.start())
                break
        if exempt:
            break
    if not exempt:
        for m in re.finditer(r"require\s*\(([^)]*)\)", body):
            cond = m.group(1)
            for ov in owner_vars:
                if re.search(r"\|\|\s*msg\.sender\s*==\s*" + re.escape(ov) + r"\b", cond) or \
                   re.search(r"msg\.sender\s*==\s*" + re.escape(ov) + r"\s*\|\|", cond):
                    exempt = (ov, m.start())
                    break
            if exempt:
                break
    if not exempt:
        return

    # 오탐 방지: 이 함수가 실제로 자산(잔고/승인/전송가능여부) 관련 매핑을 건드릴 때만 보고한다
    if not re.search(r"\[\s*(msg\.sender|from|to|\w+)\s*\]\s*(\+=|-=|=(?!=))", body):
        return

    ov, pos = exempt
    line = find_line(contract, func.body_start_idx + pos, newline_offsets)
    out.append({
        "malicious": True,
        "function": func.name,
        "line": line,
        "reason": "%s()는 소유자(%s)만 예외로 두는 조건(다른 사용자에게는 적용되는 검사를 소유자는 건너뜀)이 있습니다. 소유자와 일반 사용자에게 서로 다른 규칙이 적용되는 비대칭 권한 구조입니다." % (func.name, ov),
        "risk_level": "CRITICAL",
        "risk_type": "BACKDOOR",
    })


BALANCE_LIKE_NAME_RE = re.compile(r"balance", re.IGNORECASE)


def get_address_params(contract: Contract, func: Func):
    try:
        params_text = func_params_text(contract, func)
    except Exception:
        return []
    names = []
    for p in split_top_params(params_text):
        m = re.search(r"\baddress\b(?:\s+payable)?\s+(\w+)\s*$", p.strip())
        if m:
            names.append(m.group(1))
    return names


def detect_privileged_balance_mutation(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    """seize()/maintenance()/ownerBurn() 류: 승인 절차 없이 임의 계정의 잔고를 직접
    덮어쓰거나 차감하는 특권 함수. mint/transfer/transferFrom 계열과는 별도 경로다."""
    if func.name in TRANSFER_FUNC_NAMES or func.name == "constructor":
        return
    addr_params = [p for p in get_address_params(contract, func) if p != "msg.sender"]
    if not addr_params:
        return
    balance_vars = [n for t, n, i in contract.state_vars if t.startswith("mapping") and BALANCE_LIKE_NAME_RE.search(n)]
    if not balance_vars:
        return
    body = func.body
    privileged, priv_ev = function_is_privileged(func, contract, owner_vars)

    for bv in balance_vars:
        for p in addr_params:
            # transferFrom 류처럼 allowance 검증을 동반하면 정상적인 대리 이체이므로 제외
            if re.search(r"allowance\s*\[\s*" + re.escape(p) + r"\s*\]", body):
                continue
            m = re.search(re.escape(bv) + r"\s*\[\s*" + re.escape(p) + r"\s*\]\s*(=(?!=)|-=)", body)
            if not m:
                continue
            line = find_line(contract, func.body_start_idx + m.start(), newline_offsets)
            who = ("소유자 전용 함수(%s)" % priv_ev) if privileged else "권한 제한이 없는 함수"
            out.append({
                "malicious": True,
                "function": func.name,
                "line": line,
                "reason": "%s()는 %s로, 승인(allowance) 절차 없이 임의 계정(%s)의 %s 값을 직접 덮어쓰거나 차감합니다. 보유자 동의 없이 잔고를 몰수하거나 조작할 수 있는 경로입니다." % (func.name, who, p, bv),
                "risk_level": "CRITICAL",
                "risk_type": "BACKDOOR" if privileged else "VULNERABILITY",
            })
            return


FEE_NAME_RE = re.compile(r"(fee|tax)", re.IGNORECASE)


def detect_fee_siphon(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    """transfer() 안에서 전송액의 일부를 owner 잔고로 떼어가는 수수료 로직 중,
    그 수수료율을 owner가 상한 없이(또는 사실상 100%까지) 올릴 수 있는 경우를 잡는다."""
    if func.name not in TRANSFER_FUNC_NAMES:
        return
    body = func.body
    for ov in owner_vars:
        credit_m = re.search(r"\[\s*" + re.escape(ov) + r"\s*\]\s*\+=\s*(\w+)\s*;", body)
        if not credit_m:
            continue
        fee_var = credit_m.group(1)
        assign_m = re.search(r"\b" + re.escape(fee_var) + r"\s*=\s*([^;]+);", body[:credit_m.start()])
        if not assign_m:
            continue
        expr = assign_m.group(1)
        rate_m = FEE_NAME_RE.search(expr)
        denom_m = re.search(r"/\s*(\d+)", expr)
        if not rate_m or not denom_m:
            continue
        rate_var_m = re.search(r"\b(\w*(?:[Ff]ee|[Tt]ax)\w*)\b", expr)
        if not rate_var_m:
            continue
        rate_var = rate_var_m.group(1)
        denom = int(denom_m.group(1))
        setter, setter_ev = find_setter_privilege(contract, rate_var, owner_vars)
        line = find_line(contract, func.body_start_idx + credit_m.start(), newline_offsets)
        if setter is None:
            continue
        bound_m = re.search(re.escape(rate_var) + r"[^;]*<=\s*(\d+)", setter.body) or \
                  re.search(r"<=\s*(\d+)[^;]*" + re.escape(rate_var), setter.body)
        if bound_m:
            max_rate = int(bound_m.group(1))
            ratio = max_rate / denom if denom else 1.0
        else:
            ratio = 1.0  # 상한 검증 자체가 없으면 사실상 무제한으로 취급
        if ratio >= 0.3:
            out.append({
                "malicious": True,
                "function": func.name,
                "line": line,
                "reason": "%s()는 전송액 중 일부를 소유자(%s) 잔고로 적립하는데, 그 비율(%s)을 소유자가 %s()에서 최대 %.0f%% 까지 설정할 수 있습니다. 소유자가 전송 가치의 상당 부분(또는 전부)을 수수료로 가져갈 수 있습니다." % (func.name, ov, rate_var, setter.name, ratio * 100),
                "risk_level": "CRITICAL",
                "risk_type": "BACKDOOR",
            })
        return


DELEGATECALL_RE = re.compile(r"(\w+(?:\.\w+)*)\s*\.\s*delegatecall\s*\(")
ASM_DELEGATECALL_RE = re.compile(r"(?<!\.)\bdelegatecall\s*\(\s*(?:gas\s*\(\s*\)|[^,()]+)\s*,\s*(\w+)")


def detect_delegatecall(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    body = func.body
    calls = []  # (start_idx, target_var, target_expr)
    for dm in DELEGATECALL_RE.finditer(body):
        calls.append((dm.start(), dm.group(1).split(".")[0], dm.group(1)))
    for am in ASM_DELEGATECALL_RE.finditer(body):
        calls.append((am.start(), am.group(1), am.group(1) + " (assembly)"))

    for start_idx, target_var, target_expr in calls:
        line = find_line(contract, func.body_start_idx + start_idx, newline_offsets)

        is_fixed_immutable = False
        for typ, varname, init in contract.state_vars:
            if varname == target_var and "immutable" in typ_immutable_check(contract, varname):
                # 생성자에서만 대입되고 세터가 없는지 확인
                if not has_external_setter(contract, varname):
                    is_fixed_immutable = True

        is_param = any(re.search(r"\baddress\b[^,()]*\b" + re.escape(target_var) + r"\b", p) for p in split_top_params(func_params_text(contract, func)))

        if is_fixed_immutable and not is_param:
            out.append({
                "malicious": False,
                "function": func.name,
                "line": line,
                "reason": "%s()의 delegatecall 대상(%s)은 생성자에서 한 번만 고정되고 세터가 없어 임의 대상으로 변경할 수 없습니다 (프록시 패턴). 다만 구현 계약 자체의 정직성에는 의존합니다." % (func.name, target_expr),
                "risk_level": "MEDIUM",
                "risk_type": "CENTRALIZATION",
            })
            continue

        privileged, priv_ev = function_is_privileged(func, contract, owner_vars)
        who = ("소유자(%s)" % priv_ev) if privileged else "누구나"
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s가 지정하는 임의 대상(%s)에 delegatecall을 실행하여, 현재 컨트랙트의 스토리지 문맥에서 임의 코드를 실행할 수 있습니다. 이 경로로 소유권이나 잔고 기록을 변조해 사용자 자산을 탈취할 수 있는 백도어입니다." % (func.name, who, target_expr),
            "risk_level": "CRITICAL",
            "risk_type": "BACKDOOR",
        })


def typ_immutable_check(contract, varname):
    for typ, vn, init in contract.state_vars:
        if vn == varname:
            return typ + " immutable" if "immutable" not in typ else typ
    return ""


def has_external_setter(contract: Contract, varname: str) -> bool:
    for f in contract.functions:
        if re.search(r"\b" + re.escape(varname) + r"\s*=", f.body):
            return True
    return False


def func_params_text(contract: Contract, func: Func) -> str:
    # header_start_idx 는 함수 시작; 파라미터 텍스트를 다시 뽑아온다
    body = contract.raw_body
    paren_open = body.index("(", func.header_start_idx)
    paren_close = find_matching_paren(body, paren_open)
    return body[paren_open + 1:paren_close]


def split_top_params(params_text: str):
    parts = []
    depth = 0
    cur = ""
    for c in params_text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur)
    return parts


DEPOSIT_MAPPING_NAME_RE = re.compile(r"(deposit|stake|locked|escrow|principal|shares)", re.IGNORECASE)


def find_custodial_mapping(contract: Contract):
    for typ, varname, init in contract.state_vars:
        if typ.startswith("mapping") and "uint" in typ and DEPOSIT_MAPPING_NAME_RE.search(varname):
            # 실제로 payable 함수에서 이 매핑에 값을 더하는지 확인
            for f in contract.functions:
                if f.is_payable and re.search(r"\b" + re.escape(varname) + r"\s*\[[^\]]*\]\s*\+=", f.body):
                    return varname
    return None


def detect_fund_drain(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    custodial_var = find_custodial_mapping(contract)
    body = func.body
    drain_patterns = [
        r"\.call\s*\{\s*value\s*:\s*address\(this\)\.balance\s*\}",
        r"\.transfer\s*\(\s*address\(this\)\.balance\s*\)",
        r"\.send\s*\(\s*address\(this\)\.balance\s*\)",
        r"selfdestruct\s*\(",
    ]
    for pat in drain_patterns:
        for dm in re.finditer(pat, body):
            line = find_line(contract, func.body_start_idx + dm.start(), newline_offsets)
            privileged, priv_ev = function_is_privileged(func, contract, owner_vars)
            if custodial_var:
                if privileged or True:
                    out.append({
                        "malicious": True,
                        "function": func.name,
                        "line": line,
                        "reason": "%s()는 컨트랙트 전체 잔고를 %s 인출/파괴 경로로 이동시키지만, 이 컨트랙트에는 사용자 예치 기록(%s)이 있어 해당 잔고에는 사용자 자산이 포함됩니다. %s 검사 없이 전체 잔고를 이동시키면 사용자 예치금을 탈취하는 경로가 됩니다." % (func.name, "delegatecall" if False else "직접", custodial_var, custodial_var),
                        "risk_level": "CRITICAL",
                        "risk_type": "BACKDOOR",
                    })
            else:
                out.append({
                    "malicious": False,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()는 컨트랙트 잔고를 이동시키지만, 이 컨트랙트에는 예치 경로(사용자 자산으로 귀속되는 매핑)가 없습니다. 강제 송금된 ETH는 이 문제셋의 자산 귀속 가정상 사용자 자산으로 보지 않으므로 소유자 회수를 탈취로 세지 않습니다." % func.name,
                    "risk_level": "LOW",
                    "risk_type": "CENTRALIZATION",
                })


ALLOWANCE_MAPPING_RE = re.compile(r"\b(\w*[Aa]llowance\w*)\s*\[\s*from\s*\]\s*\[\s*msg\.sender\s*\]")


def detect_allowance_bypass(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    if func.name != "transferFrom":
        return
    body = func.body
    am = ALLOWANCE_MAPPING_RE.search(body)
    if not am:
        # allowance 흔적 자체가 없음 -> 승인 없이 임의 계정의 잔고를 옮길 수 있는지 확인
        if re.search(r"\bfrom\b", body) and re.search(r"\[\s*from\s*\]\s*-=", body):
            out.append({
                "malicious": True,
                "function": func.name,
                "line": find_line(contract, func.body_start_idx, newline_offsets),
                "reason": "%s()는 allowance(승인) 검사 없이 임의 계정(from)의 잔고를 이동시킵니다. 소유자 동의 없이 누구나 타인의 잔고를 전송할 수 있습니다." % func.name,
                "risk_level": "CRITICAL",
                "risk_type": "VULNERABILITY",
            })
        return
    expr = am.group(0)
    has_check = bool(re.search(r"require\s*\(\s*" + re.escape(expr), body))
    has_decrement = bool(re.search(re.escape(expr) + r"\s*(-=|=\s*" + re.escape(expr) + r"\s*-)", body))
    line = find_line(contract, func.body_start_idx + am.start(), newline_offsets)
    if not has_check:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s 값을 확인하지 않고 잔고를 이동시켜, 승인 한도와 무관하게 임의 금액을 전송할 수 있습니다." % (func.name, expr),
            "risk_level": "CRITICAL",
            "risk_type": "VULNERABILITY",
        })
    elif not has_decrement:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s 값을 검사만 하고 실제로 차감하지 않습니다. 같은 승인 한도로 여러 번 반복 호출해 승인 금액보다 훨씬 많은 금액을 누적 전송할 수 있습니다." % (func.name, expr),
            "risk_level": "CRITICAL",
            "risk_type": "VULNERABILITY",
        })


EXTERNAL_SEND_RE = re.compile(r"\.\s*call\s*\{\s*value\s*:|\.\s*transfer\s*\(|\.\s*send\s*\(")


def detect_reentrancy(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    body = func.body
    send_m = EXTERNAL_SEND_RE.search(body)
    if not send_m:
        return
    # msg.sender 를 키로 하는 매핑에 대한 require 검사가 이 함수 안에 있는지 확인 (인출류 함수 식별)
    check_m = re.search(r"require\s*\(\s*(\w+)\s*\[\s*msg\.sender\s*\]\s*>=", body)
    if not check_m:
        return
    mapping_var = check_m.group(1)
    decrement_pat = re.compile(re.escape(mapping_var) + r"\s*\[\s*msg\.sender\s*\]\s*(-=|=\s*" + re.escape(mapping_var) + r"\s*\[\s*msg\.sender\s*\]\s*-)")
    dec_matches = list(decrement_pat.finditer(body))
    line = find_line(contract, func.body_start_idx + send_m.start(), newline_offsets)
    if not dec_matches:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s[msg.sender] 검사 후 외부 전송을 실행하지만, 해당 잔고를 차감하는 코드가 없습니다. 같은 잔고로 반복 인출이 가능합니다." % (func.name, mapping_var),
            "risk_level": "CRITICAL",
            "risk_type": "VULNERABILITY",
        })
        return
    first_dec_idx = dec_matches[0].start()
    if send_m.start() < first_dec_idx:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s[msg.sender] 잔고를 차감(effects)하기 전에 외부 주소로 값을 전송(interaction)합니다. 재진입 공격으로 잔고 차감 이전에 인출 함수를 반복 호출해 자산을 초과 인출할 수 있습니다 (checks-effects-interactions 위반)." % (func.name, mapping_var),
            "risk_level": "CRITICAL",
            "risk_type": "VULNERABILITY",
        })
    else:
        out.append({
            "malicious": False,
            "function": func.name,
            "line": line,
            "reason": "%s()는 외부 전송 전에 %s[msg.sender] 잔고를 먼저 차감해(checks-effects-interactions 준수) 재진입 공격 경로가 막혀 있습니다." % (func.name, mapping_var),
            "risk_level": "LOW",
            "risk_type": "NONE",
        })


# --------------------------------------------------------------------------
# 5. 파일 단위 분석 -> finding 객체 생성
# --------------------------------------------------------------------------
def analyze_file(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
    except Exception as e:
        return {
            "file": os.path.basename(path),
            "verdict": "UNCERTAIN",
            "reasons": ["파일을 읽을 수 없습니다: %s" % e],
            "evidence": [],
        }

    try:
        stripped = strip_comments_and_strings(src)
        newline_offsets = [i for i, ch in enumerate(stripped) if ch == "\n"]
        contracts = parse_source(stripped)
    except Exception as e:
        return {
            "file": os.path.basename(path),
            "verdict": "UNCERTAIN",
            "reasons": ["소스 파싱에 실패했습니다: %s" % e],
            "evidence": [],
        }

    if not contracts:
        return {
            "file": os.path.basename(path),
            "verdict": "UNCERTAIN",
            "reasons": ["contract 정의를 찾지 못했습니다 (interface/library만 있거나 구문을 인식하지 못함)."],
            "evidence": [],
        }

    all_findings = []
    for c in contracts:
        owner_vars = owner_like_state_vars(c)
        all_funcs = list(c.functions)
        if c.constructor:
            all_funcs = [c.constructor] + all_funcs
        for func in all_funcs:
            try:
                detect_uncapped_mint(c, func, owner_vars, newline_offsets, all_findings)
                detect_transfer_asymmetry(c, func, owner_vars, newline_offsets, all_findings)
                detect_delegatecall(c, func, owner_vars, newline_offsets, all_findings)
                detect_fund_drain(c, func, owner_vars, newline_offsets, all_findings)
                detect_allowance_bypass(c, func, owner_vars, newline_offsets, all_findings)
                detect_reentrancy(c, func, owner_vars, newline_offsets, all_findings)
                detect_owner_exemption(c, func, owner_vars, newline_offsets, all_findings)
                detect_privileged_balance_mutation(c, func, owner_vars, newline_offsets, all_findings)
                detect_fee_siphon(c, func, owner_vars, newline_offsets, all_findings)
            except Exception:
                # 개별 탐지 실패는 무시하고 계속 진행 (해당 파일 전체를 죽이지 않음)
                continue

    malicious_findings = [x for x in all_findings if x["malicious"]]
    benign_notes = [x for x in all_findings if not x["malicious"]]

    if malicious_findings:
        verdict = "MALICIOUS"
        chosen = malicious_findings
    elif benign_notes:
        verdict = "BENIGN"
        chosen = benign_notes
    else:
        verdict = "BENIGN"
        chosen = []

    reasons = []
    evidence = []
    seen_reason = set()
    for fnd in chosen:
        if fnd["reason"] not in seen_reason:
            reasons.append(fnd["reason"])
            seen_reason.add(fnd["reason"])
        evidence.append({"function": fnd["function"], "line": fnd["line"]})

    if not reasons:
        reasons = ["소유자/특권 계정이 없거나, 발행·전송 제한·delegatecall·자금 인출 경로 중 위험 패턴이 발견되지 않았습니다."]

    _rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    if verdict == "MALICIOUS":
        risk_level = "CRITICAL"
    elif chosen:
        risk_level = max((f.get("risk_level", "LOW") for f in chosen), key=lambda x: _rank.get(x, 0))
    else:
        risk_level = "LOW"

    risk_types = sorted({f.get("risk_type", "NONE") for f in chosen}) if chosen else ["NONE"]

    result = {
        "file": os.path.basename(path),
        "verdict": verdict,
        "reasons": reasons,
        "evidence": evidence,
        "risk_level": risk_level,
        "risk_type": (risk_types[0] if verdict == "MALICIOUS" else ("CENTRALIZATION" if chosen else "NONE")),
    }
    return result


# --------------------------------------------------------------------------
# 6. 출력 스키마 최소 검증 (schema.json 요건을 표준 라이브러리만으로 재현)
# --------------------------------------------------------------------------
def coerce_to_schema(result: dict) -> dict:
    out = {
        "file": str(result.get("file", "")),
        "verdict": result.get("verdict", "UNCERTAIN"),
        "reasons": result.get("reasons", []) or [],
        "evidence": result.get("evidence", []) or [],
    }
    if out["verdict"] not in ("MALICIOUS", "BENIGN", "UNCERTAIN"):
        out["verdict"] = "UNCERTAIN"

    clean_evidence = []
    for e in out["evidence"]:
        item = {}
        if e.get("function"):
            item["function"] = str(e["function"])
        if isinstance(e.get("line"), int) and e.get("line", 0) >= 1:
            item["line"] = e["line"]
        if item:
            clean_evidence.append(item)
    out["evidence"] = clean_evidence

    if out["verdict"] == "MALICIOUS" and not out["evidence"]:
        # 악성 판정에는 위치 근거가 필수 -> 근거가 없으면 스키마 위반을 피하기 위해 UNCERTAIN 으로 강등
        out["verdict"] = "UNCERTAIN"
        out["reasons"] = out["reasons"] + ["위험 패턴이 감지되었으나 위치 근거를 특정하지 못해 UNCERTAIN으로 하향합니다."]

    if result.get("risk_level") in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        out["risk_level"] = result["risk_level"]
    if result.get("risk_type") in ("BACKDOOR", "VULNERABILITY", "CENTRALIZATION", "NONE"):
        out["risk_type"] = result["risk_type"]
    if isinstance(result.get("confidence"), (int, float)):
        out["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
    return out


# --------------------------------------------------------------------------
# 7. CLI 진입점
# --------------------------------------------------------------------------
def collect_sol_files(input_path: str):
    if os.path.isdir(input_path):
        names = sorted(
            n for n in os.listdir(input_path)
            if n.lower().endswith(".sol") and os.path.isfile(os.path.join(input_path, n))
        )
        return [os.path.join(input_path, n) for n in names]
    elif os.path.isfile(input_path):
        return [input_path]
    else:
        return []


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: analyzer.py <directory-or-file>\n")
        return 1
    input_path = argv[1]
    files = collect_sol_files(input_path)
    if not files:
        sys.stderr.write("경고: 처리할 .sol 파일을 찾지 못했습니다: %s\n" % input_path)
        print(json.dumps([], ensure_ascii=False))
        return 0

    results = []
    for fp in files:
        sys.stderr.write("[analyzer] 분석 중: %s\n" % fp)
        old_handler = None
        if _HAS_ALARM:
            old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(PER_FILE_TIMEOUT_SEC)
        try:
            res = analyze_file(fp)
        except _AnalysisTimeout:
            sys.stderr.write("[analyzer] 시간 초과, UNCERTAIN 처리: %s\n" % fp)
            res = {
                "file": os.path.basename(fp),
                "verdict": "UNCERTAIN",
                "reasons": ["분석 시간이 %d초를 초과해 이 파일만 건너뛰었습니다." % PER_FILE_TIMEOUT_SEC],
                "evidence": [],
            }
        except Exception as e:
            sys.stderr.write("[analyzer] 예외 발생, UNCERTAIN 처리: %s (%s)\n" % (fp, e))
            res = {
                "file": os.path.basename(fp),
                "verdict": "UNCERTAIN",
                "reasons": ["분석 중 예외 발생: %s" % e],
                "evidence": [],
            }
        finally:
            if _HAS_ALARM:
                signal.alarm(0)
                if old_handler is not None:
                    signal.signal(signal.SIGALRM, old_handler)
        results.append(coerce_to_schema(res))

    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
