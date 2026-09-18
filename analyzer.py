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
    first_inc_idx = inc_matches[0].start()
    pre_segment = body[:first_inc_idx]
    capped = False
    cap_evidence = None
    # 명명된 cap 변수 사용 (상태변수 혹은 하드코딩 상수 모두 포함)
    for cond_m in re.finditer(r"(require|if)\s*\(([^;{]*(?:<=|<)[^;{]*)\)", pre_segment):
        cond = cond_m.group(2)
        if "totalSupply" in cond or "amount" in cond or "supply" in cond.lower():
            if CAP_NAME_RE.search(cond) or re.search(r"<=?\s*\d", cond):
                capped = True
                cap_evidence = cond.strip()
                break
    if capped:
        out.append({
            "malicious": False,
            "function": func.name,
            "line": find_line(contract, func.body_start_idx + first_inc_idx, newline_offsets),
            "reason": "%s()는 발행 전 공급량 상한을 코드로 강제합니다 (%s). 상한 내 희석은 위험으로 부기하되 verdict는 BENIGN입니다." % (func.name, cap_evidence),
            "risk_level": "LOW",
            "risk_type": "CENTRALIZATION",
        })
        return

    line = find_line(contract, func.body_start_idx + first_inc_idx, newline_offsets)
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

    for gm in re.finditer(r"require\s*\(\s*(!?)\s*(\w+)\s*(\[\s*(msg\.sender|from|sender)\s*\])?\s*[,)]", body):
        neg, varname, has_index, idxname = gm.group(1), gm.group(2), gm.group(3), gm.group(4)
        line = find_line(contract, func.body_start_idx + gm.start(), newline_offsets)
        if varname in mapping_gate_names and has_index:
            setter, setter_ev = find_setter_privilege(contract, varname, owner_vars)
            if setter is not None:
                out.append({
                    "malicious": True,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()는 %s[%s] 값을 근거로 전송 가능 여부를 결정하며, 이 값은 %s()에서 소유자만 변경할 수 있습니다(%s). 소유자가 임의로 보유자의 전송 가능 여부를 결정하는 비대칭 구조입니다." % (func.name, varname, idxname, setter.name, setter_ev),
                    "risk_level": "CRITICAL",
                    "risk_type": "BACKDOOR",
                })
            continue
        if varname in global_flag_names and not has_index:
            # 소유자를 조건식에서 명시적으로 예외처리하는지 확인 (같은 require 문 내부 또는 직전 5줄)
            window = body[max(0, gm.start() - 200):gm.start() + 200]
            exempts_owner = False
            for ov in owner_vars:
                if re.search(r"msg\.sender\s*(==|!=)\s*" + re.escape(ov), window) or \
                   re.search(re.escape(ov) + r"\s*(==|!=)\s*msg\.sender", window):
                    exempts_owner = True
                    break
            if exempts_owner:
                out.append({
                    "malicious": True,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()의 전송 제한(%s)이 소유자에게는 예외적으로 적용되지 않아, 소유자만 팔 수 있고 일반 보유자는 팔 수 없는 비대칭 구조입니다." % (func.name, varname),
                    "risk_level": "CRITICAL",
                    "risk_type": "BACKDOOR",
                })
            else:
                out.append({
                    "malicious": False,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()의 전송 제한(%s)은 소유자를 포함해 모든 주소에 동일하게 적용되는 대칭적 가용성 제약이므로 자산이 남의 손으로 넘어가는 경로가 아닙니다. 다만 소유자가 이 플래그를 제어한다면 중앙화 위험으로 부기합니다." % (func.name, varname),
                    "risk_level": "LOW",
                    "risk_type": "CENTRALIZATION",
                })


DELEGATECALL_RE = re.compile(r"(\w+(?:\.\w+)*)\s*\.\s*delegatecall\s*\(")


def detect_delegatecall(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    body = func.body
    for dm in DELEGATECALL_RE.finditer(body):
        target_expr = dm.group(1)
        line = find_line(contract, func.body_start_idx + dm.start(), newline_offsets)
        target_var = target_expr.split(".")[0]

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
