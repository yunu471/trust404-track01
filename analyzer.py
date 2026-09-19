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
import time

def positive_seconds(name, default, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
        return min(value, maximum) if value > 0 else default
    except ValueError:
        return default


PER_FILE_TIMEOUT_SEC = positive_seconds("TRUST404_PER_FILE_TIMEOUT", 20, 540)
TOTAL_TIMEOUT_SEC = positive_seconds("TRUST404_TOTAL_TIMEOUT", 540, 540)


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
    if in_block_comment or in_string:
        raise ValueError("닫히지 않은 주석 또는 문자열")
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
        self.state_qualifiers = {}
        self.constructor = None  # Func or None
        self.raw_body = ""
        self.body_start_idx = 0


def top_level_statements(body):
    """함수 내부 지역변수를 제외하고 같은 줄의 연속 선언도 분리한다."""
    start, depth = 0, 0
    for i, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                start = i + 1
        elif ch == ";" and depth == 0:
            yield body[start:i + 1]
            start = i + 1


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

        for statement in top_level_statements(body):
            sv = STATE_VAR_RE.match(statement)
            if not sv:
                continue
            typ = sv.group(1).strip()
            varname = sv.group(3)
            init = (sv.group(5) or "").strip()
            c.state_vars.append((typ, varname, init))
            c.state_qualifiers[varname] = set(re.findall(r"\b(?:constant|immutable)\b", statement[:sv.start(3)]))

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
    return [name for typ, name, _ in contract.state_vars if typ.startswith("address")]


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
    head = func.body
    for ov in owner_vars:
        for _, condition in required_conditions(head):
            if "||" not in condition and re.search(r"(?:\bmsg\.sender\s*==\s*" + re.escape(ov) + r"\b|\b" + re.escape(ov) + r"\s*==\s*msg\.sender\b)", condition):
                return True, "inline msg.sender == %s check" % ov
    return False, ""


def find_line(contract: Contract, local_idx: int, newline_offsets) -> int:
    return line_of(contract.body_start_idx + local_idx, newline_offsets)


# --------------------------------------------------------------------------
# 4. 탐지 규칙 (Detectors)
#    각 함수는 findings 리스트에 dict 를 추가한다:
#    {malicious: bool, uncertain: bool (optional), function, line, reason, ...}
# --------------------------------------------------------------------------
CAP_NAME_RE = re.compile(r"(max[_a-z]*supply|supply[_a-z]*cap|hard[_ ]?cap|\bcap\b|mint[_a-z]*limit|_?cap_?)", re.IGNORECASE)
SUPPLY_INCREASE_RE = re.compile(r"\btotalSupply\s*(\+=|=\s*totalSupply\s*\+)")
BALANCE_INCREASE_RE = re.compile(r"\b(\w+)\s*\[\s*(\w+)\s*\]\s*\+=")


def required_conditions(body):
    """괄호 중첩을 보존하며 최상위 require 조건만 반환한다."""
    for match in re.finditer(r"\brequire\s*\(", body):
        prefix = body[:match.start()]
        if prefix.count("{") != prefix.count("}"):
            continue
        end = find_matching_paren(body, match.end() - 1)
        args = split_top_params(body[match.end():end])
        if args:
            yield match.start(), args[0]


def guard_conditions(body):
    """다음 문장까지 도달하려면 참이어야 하는 조건만 반환한다.

    if 조건을 검사했다는 사실만으로 안전하다고 보지 않는다. 실패 분기가
    곧바로 revert/return하는 단순 형태에 한해 반대 조건을 도출한다.
    """
    yield from required_conditions(body)
    for match in re.finditer(r"\bif\s*\(", body):
        prefix = body[:match.start()]
        if prefix.count("{") != prefix.count("}"):
            continue
        end = find_matching_paren(body, match.end() - 1)
        tail = body[end + 1:].lstrip()
        if tail.startswith("{"):
            close = find_matching_brace(tail, 0)
            branch = tail[1:close].strip()
        else:
            branch = tail.split(";", 1)[0].strip() + ";"
        if not re.fullmatch(r"(?:revert(?:\s+\w+)?\s*\([^;{}]*\)|return)\s*;", branch):
            continue
        condition = unwrap_condition(body[match.end():end])
        if condition.startswith("!") and not condition.startswith("!="):
            yield match.start(), unwrap_condition(condition[1:])
        elif not re.search(r"&&|\|\||!", condition):
            comparison = re.fullmatch(r"(.+?)\s*(>=|<=|>|<)\s*(.+)", condition)
            if comparison:
                inverse = {">": "<=", ">=": "<", "<": ">=", "<=": ">"}
                yield match.start(), comparison[1] + inverse[comparison[2]] + comparison[3]


def unwrap_condition(condition):
    condition = condition.strip()
    while condition.startswith("(") and find_matching_paren(condition, 0) == len(condition) - 1:
        condition = condition[1:-1].strip()
    return condition


def mandatory_terms(condition):
    """AND 항만 분해하여 OR·부정식을 양의 상한 조건과 혼동하지 않는다."""
    condition = unwrap_condition(condition)
    depth, start, parts = 0, 0, []
    for i, ch in enumerate(condition):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and condition[i:i + 2] == "||":
            return
        elif depth == 0 and condition[i:i + 2] == "&&":
            parts.append(condition[start:i])
            start = i + 2
    if parts:
        for part in parts + [condition[start:]]:
            yield from mandatory_terms(part)
    elif not condition.startswith("!"):
        yield condition


def external_guard(body, identifier):
    for _, condition in required_conditions(body):
        if ("||" not in condition and re.search(r"\b" + re.escape(identifier) + r"\b", condition)
                and re.search(r"\b(?!abi\b)\w+\s*\.\s*\w+\s*\(", condition)):
            return True
    return False


def detect_uncapped_mint(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    if func.name == "constructor":
        return
    body = func.body
    supply_name = "totalSupply"
    # 수량 상태변수와 잔고가 같은 값만큼 증가하는 구조로 발행을 인식한다.
    if not SUPPLY_INCREASE_RE.search(body) and not func.is_payable:
        for typ, name, _ in contract.state_vars:
            if not typ.startswith("uint"):
                continue
            increase = re.search(r"\b" + re.escape(name) + r"\s*\+=\s*(\w+)\b[^;]*;", body)
            if increase and re.search(r"\w+\s*\[[^\]]+\]\s*\+=\s*" + re.escape(increase[1]) + r"\s*;", body):
                supply_name = name
                break
    inc_matches = list(re.finditer(r"\b" + re.escape(supply_name) + r"\s*(\+=|=\s*" + re.escape(supply_name) + r"\s*\+)", body))
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
    for cond in (term for _, condition in guard_conditions(pre_segment)
                 for term in mandatory_terms(condition)):
        if "||" not in cond:
            bound = re.fullmatch(r"\s*" + re.escape(supply_name) + r"\s*\+\s*(\w+)\s*<=?\s*([\w.]+(?:\([^;]*\))?)\s*", cond)
            if bound:
                capped = True
                cap_evidence = cond.strip()
                checked_amount_var = bound.group(1)
                cap_var = bound.group(2)
                break
    line = find_line(contract, func.body_start_idx + first_inc_idx, newline_offsets)

    if capped and len(inc_matches) > 1:
        out.append(uncertainty_finding(
            "%s()는 공급량을 여러 번 증가시킵니다. 개별 상한 검사와 누적 증가량의 관계를 현재 분석 범위에서 확정할 수 없습니다." % func.name,
            line, func.name))
        return

    if capped:
        if external_guard(pre_segment, supply_name):
            out.append(uncertainty_finding(
                "%s()의 발행량(%s)은 외부 정책 반환값으로 제한됩니다. 그 구현 없이 상한의 실효성을 확정할 수 없습니다." % (func.name, supply_name), line, func.name))
            return
        # (a) 실제 증가량이 검사한 변수와 일치하는지 확인 ("가짜 상한" - 검사와 효과의 불일치)
        rhs_end = body.find(";", first_inc.end())
        rhs_text = body[first_inc.end():rhs_end].strip() if rhs_end != -1 else ""
        rhs_norm = re.sub(r"[\s()]+", "", rhs_text)
        if checked_amount_var and rhs_text and rhs_norm != checked_amount_var:
            out.append({
                "malicious": True,
                "function": func.name,
                "line": line,
                "reason": "%s()는 상한 검사에서 %s 값을 검사하지만, 실제로 공급량에 더하는 값은 '%s'로 서로 일치하지 않습니다. 검사는 통과하면서 실제 발행량은 검사되지 않은 만큼 늘어날 수 있어 상한이 무력화됩니다." % (func.name, checked_amount_var, rhs_text),
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
            is_fixed = bool(contract.state_qualifiers.get(cap_var, set()) & {"constant", "immutable"})
            if cap_type is not None and not is_fixed:
                setter, setter_ev = find_setter_privilege(contract, cap_var, owner_vars)
                if setter is not None:
                    assignment = re.search(r"\b" + re.escape(cap_var) + r"\s*=\s*(\w+)\s*;", setter.body)
                    bounded = False
                    if assignment:
                        for _, condition in guard_conditions(setter.body[:assignment.start()]):
                            for term in mandatory_terms(condition):
                                bound = re.fullmatch(re.escape(assignment[1]) + r"\s*<=?\s*(\w+)", term)
                                if bound and (bound[1].isdigit() or contract.state_qualifiers.get(bound[1], set()) & {"constant", "immutable"}):
                                    bounded = True
                    if not bounded:
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

    # 발행을 감싼 조건 분기나 발행 뒤 revert 검사는 단순 선행 검사와 다르다.
    # 이를 추적하지 못했다는 이유로 '무제한 발행'을 확정하지 않는다.
    enclosing_branch = pre_segment.count("{") != pre_segment.count("}")
    post_guard = any(re.search(r"\b" + re.escape(supply_name) + r"\b", condition)
                     for _, condition in guard_conditions(body[first_inc.end():]))
    if enclosing_branch or post_guard:
        out.append(uncertainty_finding(
            "%s()의 공급량 증가는 중첩 분기 또는 사후 검사와 연결되어 있습니다. 모든 발행 경로에 상한이 강제되는지 현재 분석 범위에서 확정할 수 없습니다." % func.name,
            line, func.name))
        return

    if privileged:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s 로 소유자 전용이며, 공급량을 증가시키기 전에 공급량 상한을 검사하지 않습니다. 소유자가 발행량을 무제한으로 늘려 보유자 지분을 희석할 수 있습니다." % (func.name, priv_evidence),
            "risk_level": "CRITICAL",
            "risk_type": "BACKDOOR",
        })
    else:
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 호출 권한 제한이 없고 공급량 상한 검사도 없어, 누구나 임의로 공급량/잔고를 증가시킬 수 있습니다." % func.name,
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
    # 이름(whitelist/blacklist/...)에 의존하지 않고, mapping(address => bool) 형태의
    # per-address bool 매핑은 전부 게이트 후보로 본다. 실제 악성 여부는 "owner만 바꿀 수
    # 있는가"(find_setter_privilege)로 걸러지므로 이름 의존을 없애도 오탐 위험이 낮다.
    mapping_gate_names = {n for t, n, i in contract.state_vars if t.startswith("mapping") and "bool" in t}
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
            # 기본 허용 + 송신자/수신자 모두에 같은 deny 정책을 적용하는 경우,
            # 규제 정책인지 선택적 동결 악용인지 소스만으로 확정하지 않는다.
            addresses = get_address_params(contract, func)
            terms = [r"!\s*" + re.escape(gate_name) + r"\s*\[\s*" + re.escape(addr) + r"\s*\]"
                     for addr in addresses]
            sender_term = r"!\s*" + re.escape(gate_name) + r"\s*\[\s*msg\.sender\s*\]"
            bilateral_deny = cm.group(1) == "require" and any(
                re.fullmatch(r"\s*(?:" + sender_term + r"\s*&&\s*" + term +
                             r"|" + term + r"\s*&&\s*" + sender_term + r")\s*(?:,\s*)?", cond)
                for term in terms)
            if bilateral_deny:
                finding = uncertainty_finding(
                    "%s()는 송신자와 수신자 모두에 관리자 변경 가능한 차단 정책(%s)을 적용합니다. 정상적인 차단 정책인지 선택적 동결 악용인지 운영 근거 없이 확정할 수 없습니다." % (func.name, gate_name),
                    line, func.name)
                finding["risk_type"] = "CENTRALIZATION"
                out.append(finding)
                continue
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
    balance_vars = [n for t, n, i in contract.state_vars if re.fullmatch(r"mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)", t)]
    balance_vars = [n for n in balance_vars if BALANCE_LIKE_NAME_RE.search(n) or (
        contract.constructor and re.search(r"\b" + re.escape(n) + r"\s*\[\s*msg\.sender\s*\]\s*=", contract.constructor.body))]
    if not balance_vars:
        return
    body = func.body
    privileged, priv_ev = function_is_privileged(func, contract, owner_vars)

    for bv in balance_vars:
        for p in addr_params:
            # transferFrom 류처럼 allowance 검증을 동반하면 정상적인 대리 이체이므로 제외
            if re.search(r"(?i)\w*allow\w*\s*\[\s*" + re.escape(p) + r"\s*\]", body):
                continue
            m = re.search(re.escape(bv) + r"\s*\[\s*" + re.escape(p) + r"\s*\]\s*(=(?!=)|-=)", body)
            if not m:
                continue
            if external_guard(body[:m.start()], p):
                continue
            if not privileged and not BALANCE_LIKE_NAME_RE.search(bv):
                continue  # 부채/담보/설정 장부를 이름 없는 토큰 잔고로 단정하지 않는다.
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
        rate_m = re.search(r"\b(\w+)\s*\*\s*(\w+)\s*/\s*([\d_]+)", expr)
        if not rate_m:
            continue
        rates = [n for t, n, _ in contract.state_vars if t.startswith("uint") and n in rate_m.groups()[:2]]
        if len(rates) != 1:
            continue
        rate_var = rates[0]
        denom = int(rate_m.group(3).replace("_", ""))
        setter, setter_ev = find_setter_privilege(contract, rate_var, owner_vars)
        line = find_line(contract, func.body_start_idx + credit_m.start(), newline_offsets)

        if setter is None:
            # 세터가 없다면 -- 애초에 생성 시점 초기값 자체가 이미 높을 수 있다 (세터가
            # 없다고 안전한 게 아니라, 처음부터 고정된 고율 수수료일 수 있다)
            init_val = None
            for typ, vn, init in contract.state_vars:
                if vn == rate_var and init:
                    num_m = re.search(r"(\d+)", init)
                    if num_m:
                        init_val = int(num_m.group(1))
                    break
            if init_val is None:
                continue
            ratio = init_val / denom if denom else 1.0
            if ratio >= 0.3:
                out.append({
                    "malicious": True,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()는 전송액 중 일부를 소유자(%s) 잔고로 적립하는데, 그 비율(%s)이 세터 없이 생성 시점부터 %.0f%% 로 고정되어 있습니다. 세터가 없다는 것이 안전을 뜻하지 않으며, 이미 처음부터 전송 가치의 상당 부분을 소유자가 가져가는 구조입니다." % (func.name, ov, rate_var, ratio * 100),
                    "risk_level": "CRITICAL",
                    "risk_type": "BACKDOOR",
                })
            return

        assignment = re.search(r"\b" + re.escape(rate_var) + r"\s*=\s*(\w+)\s*;", setter.body)
        bound_value = None
        if assignment:
            for _, condition in required_conditions(setter.body[:assignment.start()]):
                bound_m = re.search(r"\b" + re.escape(assignment[1]) + r"\s*<=\s*(\w+)", condition)
                if bound_m and "||" not in condition:
                    literal = bound_m[1]
                    for _, n, init in contract.state_vars:
                        if n == literal and "constant" in contract.state_qualifiers.get(n, set()):
                            literal = init
                    if re.fullmatch(r"[\d_]+", literal):
                        bound_value = int(literal.replace("_", ""))
        if bound_value is not None:
            max_rate = bound_value
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

        # fallback의 상태변수 기반 프록시와 호출자가 매번 대상을 전달하는
        # 실행기를 구분한다. 저장소 회계가 있거나 비특권 변경 경로가 있으면 제외.
        resolved_target = target_var
        alias = re.search(r"\baddress\s+" + re.escape(target_var) + r"\s*=\s*(\w+)\s*;", body[:start_idx])
        if alias:
            resolved_target = alias.group(1)
        address_state = any(t.startswith("address") and n == resolved_target for t, n, _ in contract.state_vars)
        writers = [f for f in contract.functions if re.search(
            r"\b" + re.escape(resolved_target) + r"\s*=(?!=)", f.body)]
        externally_checked = external_guard(body[:start_idx], target_var)
        if writers:
            checks = []
            for writer in writers:
                assignment = re.search(r"\b" + re.escape(resolved_target) + r"\s*=\s*(\w+)\s*;", writer.body)
                checks.append(bool(assignment and external_guard(writer.body[:assignment.start()], assignment[1])))
            externally_checked = externally_checked or all(checks)
        if externally_checked:
            out.append(uncertainty_finding(
                "%s()의 delegatecall 대상(%s)은 외부 권한 정책의 검사를 거칩니다. 정책 구현 없이 임의 대상 허용 여부를 확정할 수 없습니다." % (func.name, target_expr), line, func.name))
            continue
        if (func.name == "fallback" and address_state and writers
                and not any(t.startswith("mapping") for t, _, _ in contract.state_vars)
                and all(function_is_privileged(f, contract, owner_vars)[0] for f in writers)):
            finding = uncertainty_finding(
                "%s()는 관리자가 변경하는 구현 주소(%s)로 위임하는 프록시입니다. 업그레이드 권한의 신뢰성과 외부 구현을 확인하지 못해 정상 업그레이드인지 백도어인지 확정할 수 없습니다." % (func.name, resolved_target),
                line, func.name)
            finding["risk_type"] = "CENTRALIZATION"
            out.append(finding)
            continue

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
                "uncertain": True,
                "function": func.name,
                "line": line,
                "reason": "%s()의 delegatecall 대상(%s)은 고정되어 있지만, 실행되는 외부 구현을 확인할 수 없어 안전성을 확정할 수 없습니다." % (func.name, target_expr),
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
            return typ + " " + " ".join(sorted(contract.state_qualifiers.get(varname, set())))
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
        if re.fullmatch(r"mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)", typ):
            # 실제로 payable 함수에서 이 매핑에 값을 더하는지 확인
            for f in contract.functions:
                if f.is_payable and re.search(r"\b" + re.escape(varname) + r"\s*\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value\s*;", f.body):
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
                # 매핑 부재는 입금 경로 부재가 아니다. buyer가 직접 입금하는
                # escrow/고정 수령 지갑을 force-send 회수라고 설명하지 않는다.
                if any(f.is_payable for f in contract.functions):
                    continue
                out.append({
                    "malicious": False,
                    "function": func.name,
                    "line": line,
                    "reason": "%s()는 컨트랙트 잔고를 이동시키지만, 이 컨트랙트에는 예치 경로(사용자 자산으로 귀속되는 매핑)가 없습니다. 강제 송금된 ETH는 이 문제셋의 자산 귀속 가정상 사용자 자산으로 보지 않으므로 소유자 회수를 탈취로 세지 않습니다." % func.name,
                    "risk_level": "LOW",
                    "risk_type": "CENTRALIZATION",
                })


ARBITRARY_CALL_RE = re.compile(r"(\w+)\s*\.\s*call\s*\{\s*value\s*:\s*(\w+)\s*\}\s*\(")


def detect_arbitrary_call_drain(contract: Contract, func: Func, owner_vars, newline_offsets, out):
    """execute()/route() 류: 임의 대상(target)에 임의 금액(value 파라미터)으로 저수준 call을
    실행하는 특권 함수. 컨트랙트에 사용자 예치 장부가 있으면, address(this).balance 라는
    리터럴을 안 써도 예치금을 임의 주소로 빼돌리는 경로가 된다."""
    body = func.body
    custodial_var = find_custodial_mapping(contract)
    if not custodial_var:
        return
    addr_params = set(get_address_params(contract, func))
    for m in ARBITRARY_CALL_RE.finditer(body):
        target_var, value_var = m.group(1), m.group(2)
        if target_var not in addr_params:
            continue  # 대상이 고정 주소면 이 규칙 대상이 아님 (다른 규칙에서 처리)
        if value_var == "0":
            continue
        privileged, priv_ev = function_is_privileged(func, contract, owner_vars)
        if not privileged:
            continue  # 권한 없는 함수는 더 심각하지만, 이 규칙은 "특권 우회 인출"에 집중
        line = find_line(contract, func.body_start_idx + m.start(), newline_offsets)
        out.append({
            "malicious": True,
            "function": func.name,
            "line": line,
            "reason": "%s()는 %s로, 함수 인자로 받은 임의 대상(%s)에 임의 금액(%s)을 저수준 call로 전송할 수 있습니다. 이 컨트랙트에는 사용자 예치 기록(%s)이 있어, address(this).balance를 직접 쓰지 않아도 예치금을 임의 주소로 우회 인출할 수 있는 경로입니다." % (func.name, priv_ev, target_var, value_var, custodial_var),
            "risk_level": "CRITICAL",
            "risk_type": "BACKDOOR",
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
            "reason": "%s()는 외부 전송 전에 %s[msg.sender] 잔고를 먼저 차감합니다. 확인한 코드 순서는 checks-effects-interactions를 따르며, 전송 전에 같은 잔고를 미차감 상태로 남기는 패턴은 없습니다." % (func.name, mapping_var),
            "risk_level": "LOW",
            "risk_type": "NONE",
        })


# --------------------------------------------------------------------------
# 5. 파일 단위 분석 -> finding 객체 생성
# --------------------------------------------------------------------------
def validate_delimiters(stripped):
    """경량 파서가 잘린 소스를 정상 계약으로 취급하지 않도록 확인한다."""
    stack = []
    pairs = {"}": "{", ")": "(", "]": "["}
    for ch in stripped:
        if ch in "{([":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                raise ValueError("괄호가 올바르게 짝지어지지 않았습니다")
    if stack:
        raise ValueError("닫히지 않은 괄호가 있습니다")


def uncertainty_finding(reason, line, function=None):
    finding = {
        "malicious": False, "uncertain": True, "reason": reason,
        "line": line, "risk_level": "MEDIUM", "risk_type": "NONE",
    }
    if function:
        finding["function"] = function
    return finding


def detect_analysis_gaps(stripped, newline_offsets, out):
    # import 해석 및 상속 결합은 이 분석기의 지원 범위 밖이다.
    for pattern, reason in (
        (r"\bimport\b", "import된 소스는 분석하지 않아 외부 의존 구현을 확인할 수 없습니다."),
        (r"\bcontract\s+\w+\s+is\b", "상속된 상태변수·함수·권한을 결합해 분석하지 못하므로 전체 동작을 확정할 수 없습니다."),
        (r"\bassembly\b", "인라인 어셈블리의 전체 효과를 분석하지 못해 안전성을 확정할 수 없습니다."),
    ):
        for match in re.finditer(pattern, stripped):
            out.append(uncertainty_finding(reason, line_of(match.start(), newline_offsets)))


def detect_uncertain_behavior(contract, func, owner_vars, newline_offsets, out):
    """위험 확정 근거와 별개로, 외부 구현/운영 정보가 필요한 경로를 기록한다."""
    # 일반 ETH 송금(call with empty data / transfer / send)은 기존 규칙이 분석한다.
    # 그 밖의 저수준 호출과 외부 메서드는 대상 구현을 볼 수 없다.
    for match in re.finditer(r"\.\s*(\w+)\s*(?:\{[^{}]*\}\s*)?\(", func.body):
        method = match.group(1)
        if re.search(r"\babi\s*$", func.body[:match.start()]):
            continue  # abi.encode/decode 등은 외부 호출이 아니다.
        if method in {"delegatecall", "transfer", "send", "push", "pop"}:
            # 주소의 transfer/send와 구분되는 토큰 인터페이스 호출은 아래에서 처리.
            if method != "transfer":
                continue
            end = find_matching_paren(func.body, match.end() - 1)
            if len(split_top_params(func.body[match.end():end])) < 2:
                continue
        if method == "call":
            end = find_matching_paren(func.body, match.end() - 1)
            if not func.body[match.end():end].strip():
                continue
        # 파일 안에 구현된 라이브러리나 this 호출까지 안전하다고 가정하지 않는다.
        out.append(uncertainty_finding(
            "%s()의 외부 호출(%s)은 대상 구현과 반환 동작을 확인할 수 없어 추가 검토가 필요합니다." % (func.name, method),
            find_line(contract, func.body_start_idx + match.start(), newline_offsets), func.name))

    # 장부 없는 공개 수신 + 특권 송금은 지갑/회수 정책과 사용자 보관금을
    # 코드만으로 구분할 수 없다. 수신 자체가 제한된 에스크로는 포함하지 않는다.
    open_receive = any(f.name == "receive" and f.is_payable and not f.body.strip()
                       for f in contract.functions)
    value_transfer = re.search(r"\.call\s*\{[^{}]*\bvalue\s*:|\.(?:transfer|send)\s*\(", func.body)
    if (open_receive and not find_custodial_mapping(contract) and value_transfer
            and function_is_privileged(func, contract, owner_vars)[0]):
        finding = uncertainty_finding(
            "%s()는 누구나 ETH를 보낼 수 있는 계약에서 관리자 권한으로 자금을 이동합니다. 소유자 자금 회수인지 사용자 보관금 인출인지 귀속 정보를 확인할 수 없습니다." % func.name,
            find_line(contract, func.body_start_idx + value_transfer.start(), newline_offsets), func.name)
        finding["risk_type"] = "CENTRALIZATION"
        out.append(finding)

    # 사용자 예치금의 시간/중단 제약을 관리자가 사후 변경할 수 있는 경우.
    custodial = find_custodial_mapping(contract)
    if custodial:
        for match in re.finditer(r"\b(?:require|if)\s*\(", func.body):
            end = find_matching_paren(func.body, match.end() - 1)
            condition = func.body[match.end():end]
            timed = bool(re.search(r"\bblock\s*\.\s*(?:timestamp|number)\b", condition))
            withdraws = bool(re.search(r"\b" + re.escape(custodial) + r"\s*\[[^\]]+\]\s*(?:-=|=(?!=))", func.body))
            for typ, name, _ in contract.state_vars:
                # 전역 bool 중단은 모든 인출자에게 적용되는 가용성 제약이다.
                # 관리자만 우회하는 경로는 owner-exemption 규칙이 별도로 탐지한다.
                if not timed:
                    if (typ == "bool" and withdraws
                            and any(pos == match.start() and unwrap_condition(cond) in {name, "!" + name}
                                    for pos, cond in required_conditions(func.body))):
                        out.append({
                            "malicious": False, "function": func.name,
                            "line": find_line(contract, func.body_start_idx + match.start(), newline_offsets),
                            "reason": "%s()는 전역 조건(%s)을 인출 전에 검사하며 이 검사에 관리자 예외가 없습니다. 이 조건은 호출자별 자산 귀속을 바꾸지 않는 대칭적 가용성 제약이므로 규정상 이 조건만으로 악성으로 분류하지 않습니다." % (func.name, condition.split(",", 1)[0].strip()),
                            "risk_level": "LOW", "risk_type": "CENTRALIZATION",
                        })
                    continue
                if re.search(r"\b" + re.escape(name) + r"\b", condition):
                    setter, _ = find_setter_privilege(contract, name, owner_vars)
                    if setter:
                        out.append(uncertainty_finding(
                            "%s()의 출금 제약(%s)을 %s()에서 관리자가 변경할 수 있어 예치금 회수 가능성을 확정할 수 없습니다." % (func.name, name, setter.name),
                            find_line(contract, func.body_start_idx + match.start(), newline_offsets), func.name))


def detect_asset_flow_risks(contract, func, owner_vars, newline_offsets, out):
    """권한/검사 → 상태 변경 → 지급을 연결하는 제한된 함수 내 흐름 분석.

    완전한 CFG/기호 실행은 아니다. 아래 증거가 한 함수 안에서 연결되는 경우만
    확정하며, 외부 정책이나 복잡한 분기는 기존 불확실성 규칙에 맡긴다.
    """
    if func.name == 'constructor':
        return
    body = func.body
    compact = lambda text: re.sub(r'\s+', '', text)
    conditions = list(required_conditions(body))
    uint_maps = [n for t, n, _ in contract.state_vars
                 if re.fullmatch(r'mapping\s*\(\s*address\s*=>\s*uint\d*\s*\)', t)]
    state_names = {n for _, n, _ in contract.state_vars}
    privileged = function_is_privileged(func, contract, owner_vars)[0]

    def report(offset, reason, uncertain=False):
        finding = uncertainty_finding(reason, find_line(contract, func.body_start_idx + offset, newline_offsets), func.name)
        if not uncertain:
            finding.update(malicious=True, uncertain=False, risk_level='HIGH', risk_type='VULNERABILITY')
        out.append(finding)

    # 지역변수의 단순 대입을 추적한다. 상태변수의 값까지 추측하지 않는다.
    def expand(expression, before):
        definitions = {}
        for m in re.finditer(r'\b(?:uint\d*|address(?:\s+payable)?|bytes32|bool)\s+(\w+)\s*=\s*([^;]+);', before):
            if m[1] not in state_names:
                definitions[m[1]] = m[2]
        for _ in range(6):
            updated = re.sub(r'\b\w+\b', lambda m: '(' + definitions[m[0]] + ')' if m[0] in definitions else m[0], expression)
            if updated == expression or len(updated) > 10000:
                break
            expression = updated
        return expression

    sends = list(re.finditer(
        r'(payable\s*\([^;{}]+?\)|msg\s*\.\s*sender|\b\w+)\s*\.\s*call\s*\{\s*value\s*:\s*([^{}]+)\}', body))

    # 공개 payable 배치에서 자기 delegatecall은 msg.value를 매번 보존한다.
    batch = re.search(r'address\s*\(\s*this\s*\)\s*\.\s*delegatecall\s*\(', body)
    if batch and func.is_payable and find_custodial_mapping(contract) and re.search(r'\b(?:for|while)\s*\(', body):
        rejects_value = any(i < batch.start() and compact(c) in {'msg.value==0', '0==msg.value'} for i, c in conditions)
        if not rejects_value and not external_guard(body[:batch.start()], 'msg.value'):
            report(batch.start(), '%s()는 payable 반복 delegatecall에서 같은 msg.value를 재사용합니다. 같은 계약의 예치 함수는 그 값을 잔고에 더하므로 한 번의 송금이 여러 번 입금으로 기록될 수 있습니다.' % func.name)

    # ERC20 반환값을 버린 뒤 전송 요청액만큼 장부를 올리는 순서.
    for call in re.finditer(r'\b(\w+)\.transferFrom\(\s*msg\.sender\s*,\s*address\(this\)\s*,\s*(\w+)\s*\)\s*;', body):
        prefix = body[:call.start()].rsplit(';', 1)[-1].strip()
        if prefix:
            continue  # require/대입/분기 등 결과 처리 여부를 여기서는 단정하지 않는다.
        credit = re.search(r'\b(\w+)\s*\[\s*msg\.sender\s*\]\s*\+=\s*' + re.escape(call[2]) + r'\s*;', body[call.end():])
        if credit and credit[1] in uint_maps:
            report(call.start(), '%s()는 %s.transferFrom의 성공 여부를 버린 뒤 요청량 %s를 사용자 장부에 적립합니다. 토큰이 false를 반환하면 입금 없는 잔고가 생깁니다.' % (func.name, call[1], call[2]))

    # unchecked 내부의 타인 수령액 증가와 연결된 자기 잔고 차감.
    for block in re.finditer(r'\bunchecked\s*\{', body):
        end = find_matching_brace(body, block.end() - 1)
        for debit in re.finditer(r'\b(\w+)\s*\[\s*msg\.sender\s*\]\s*-=\s*(\w+)\s*;', body[block.end():end]):
            ledger, amount = debit.groups()
            if ledger not in uint_maps:
                continue
            if external_guard(body[:block.start()], amount):
                continue
            checked = any(i < block.start() and '||' not in c and
                          re.search(re.escape(ledger) + r'\s*\[\s*msg\.sender\s*\]\s*>=\s*' + re.escape(amount) + r'\b', c)
                          for i, c in conditions)
            if not checked and re.search(re.escape(ledger) + r'\s*\[[^\]]+\]\s*\+=\s*' + re.escape(amount), body[block.end():end]):
                report(block.start(), '%s()는 잔고 충분성 검사 없이 unchecked에서 %s[msg.sender]를 차감하고 수령자에게 적립합니다. 언더플로로 잔고가 커져 가치 이전에 악용될 수 있습니다.' % (func.name, ledger))

    # 소유자 변경에 사용된 토큰별 승인이 이전 후에도 남는지 확인.
    address_maps = [n for t, n, _ in contract.state_vars if re.fullmatch(r'mapping\s*\(\s*uint\d*\s*=>\s*address\s*\)', t)]
    for owner_map in address_maps:
        assignment = re.search(r'\b' + re.escape(owner_map) + r'\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)\s*;', body)
        if not assignment or assignment[2] not in get_address_params(contract, func):
            continue
        if not any(i < assignment.start() and re.search(re.escape(owner_map) + r'\s*\[\s*' + re.escape(assignment[1]) + r'\s*\]', c) for i, c in conditions):
            continue  # approve()는 승인 장부만 변경하며 소유권 이전이 아니다.
        for approval in address_maps:
            if approval == owner_map:
                continue
            ref = re.escape(approval) + r'\s*\[\s*' + re.escape(assignment[1]) + r'\s*\]'
            used = any(i < assignment.start() and re.search(ref + r'\s*==\s*msg\.sender', c) for i, c in conditions)
            cleared = re.search(r'\bdelete\s+' + ref + r'\s*;|' + ref + r'\s*=\s*address\s*\(\s*0\s*\)', body)
            if used and not cleared:
                report(assignment.start(), '%s()는 %s의 토큰별 승인으로 소유권을 변경하지만 해당 승인을 지우지 않습니다. 이전 승인자가 새 소유자의 토큰을 다시 이전할 수 있습니다.' % (func.name, approval))

    for send in sends:
        prefix = body[:send.start()]
        target, value = send.groups()
        target_expr, value_expr = expand(target, prefix), expand(value, prefix)
        prior = [(i, c) for i, c in conditions if i < send.start()]
        sender_receives = compact(target) in {'msg.sender', 'payable(msg.sender)'}

        # 호출자가 수령자와 금액을 모두 정하는 공개 실행기.
        if (target in get_address_params(contract, func) and not privileged
                and func.visibility in {'external', 'public'}
                and not prior and not contract.modifiers
                and re.search(r'\buint\d*\s+' + re.escape(value.strip()) + r'\b', func_params_text(contract, func))):
            report(send.start(), '%s()는 호출 권한이나 사용자 잔고 검사 없이 인자로 받은 대상(%s)과 금액(%s)으로 계약 자금을 송금합니다. 누구나 보관 자금을 자신의 주소로 이동시킬 수 있습니다.' % (func.name, target, value))

        # 외부 정책에 tx.origin을 인자로 넘기는 것과 직접 권한 비교를 구별한다.
        for i, condition in prior:
            if re.search(r'\btx\.origin\s*==\s*\w+\b|\b\w+\s*==\s*tx\.origin\b', condition) and not privileged:
                report(i, '%s()는 지급 권한을 msg.sender 대신 tx.origin으로 검사한 뒤 %s에 송금합니다. 소유자가 중간 계약을 호출하면 그 계약이 송금 경로를 이용할 수 있습니다.' % (func.name, target))

        # 서명으로 지급하면서 사용 상태를 전혀 갱신하지 않으면 재사용 가능.
        signature = re.search(r'\becrecover\s*\(\s*(\w+)\s*,', prefix)
        if signature and not privileged:
            digest = expand(signature[1], prefix)
            consumed = False
            for _, name, _ in contract.state_vars:
                nonce_ref = r'\b' + re.escape(name) + r'\s*(?:\[[^\]]+\])?'
                if re.search(r'\b' + re.escape(name) + r'\b', digest):
                    if re.search(nonce_ref + r'\s*(?:\+=\s*[1-9]\d*\s*;|\+\+|=\s*' + nonce_ref + r'\s*\+\s*[1-9]\d*\s*;)', prefix):
                        consumed = True
                used_ref = re.escape(name) + r'\s*\[\s*' + re.escape(signature[1]) + r'\s*\]'
                if (any('||' not in c and re.search(r'!\s*' + used_ref, c) for _, c in prior)
                        and re.search(used_ref + r'\s*=\s*true\s*;', prefix)):
                    consumed = True
            if not consumed:
                report(signature.start(), '%s()는 서명 검사 후 %s를 지급하지만 서명 메시지와 연결된 nonce/사용 기록을 갱신하지 않습니다. 같은 서명을 반복 제출해 재지급을 받을 수 있습니다.' % (func.name, value))
            elif 'block.chainid' not in compact(digest) or 'address(this)' not in compact(digest):
                report(signature.start(), '%s()의 서명에는 사용 기록이 있으나 체인·계약 도메인 결합을 확인하지 못해 다른 배포본에서의 재사용 가능성을 검토해야 합니다.' % func.name, uncertain=True)

        if sender_receives and not privileged:
            # 잔고 차감량보다 사용자에게 유리하게 매번 올림하는 지급.
            rounding = re.search(r'\(\s*(\w+)\s*\+\s*([\d_]+)\s*\)\s*/\s*([\d_]+)', value_expr)
            if rounding:
                units, adjustment, divisor = rounding.groups()
                adjustment, divisor = int(adjustment.replace('_', '')), int(divisor.replace('_', ''))
                debit = any(re.search(r'\b' + re.escape(n) + r'\s*\[\s*msg\.sender\s*\]\s*-=\s*' + re.escape(units) + r'\s*;', prefix) for n in uint_maps)
                if debit and divisor > 1 and adjustment == divisor - 1:
                    report(send.start(), '%s()는 장부에서 %s 단위를 차감하지만 지급액을 (%s + %d) / %d로 매번 올림합니다. 지급을 작은 청구로 나누면 같은 차감량에 더 많은 준비금을 지급받을 수 있습니다.' % (func.name, units, units, adjustment, divisor))
            # 장부에서 읽은 지급량에 소비 상태/한도 갱신이 연결되어 있는지 확인.
            for ledger in uint_maps:
                ref = re.escape(ledger) + r'\s*\[\s*msg\.sender\s*\]'
                if not re.search(ref, value_expr):
                    continue
                consumed = bool(re.search(ref + r'\s*(?:-=|=(?!=))|\bdelete\s+' + ref, prefix))
                for typ, flag, _ in contract.state_vars:
                    if typ.startswith('mapping') and 'bool' in typ:
                        flag_ref = re.escape(flag) + r'\s*\[\s*msg\.sender\s*\]'
                        consumed |= bool(any('||' not in c and re.search(r'!\s*' + flag_ref, c) for _, c in prior) and re.search(flag_ref + r'\s*=\s*true\s*;', prefix))
                if not consumed:
                    report(send.start(), '%s()는 %s[msg.sender]에서 읽은 배정량을 지급하면서 배정량 차감이나 사용 기록 갱신을 하지 않아 같은 배정을 반복 인출할 수 있습니다.' % (func.name, ledger))

            # 공개 세터가 바꾸는 값을 담보 대비 지급 상한에 즉시 사용.
            for _, condition in prior:
                if compact(value) not in compact(condition) or not re.search(r'\w+\s*\[\s*msg\.sender\s*\]\s*\*', condition):
                    continue
                for typ, price, _ in contract.state_vars:
                    if not typ.startswith('uint') or not re.search(r'\b' + re.escape(price) + r'\b', condition):
                        continue
                    for setter in contract.functions:
                        assignment = re.search(r'\b' + re.escape(price) + r'\s*=\s*(\w+)\s*;', setter.body)
                        if (assignment and setter.visibility in {'external', 'public'}
                                and not function_is_privileged(setter, contract, owner_vars)[0]
                                and not list(required_conditions(setter.body)) and not contract.modifiers):
                            report(send.start(), '%s()의 담보 대비 지급 상한은 %s에 의존하지만 %s()에서 호출 제한 없이 그 값을 바꿀 수 있습니다. 값을 부풀려 과도한 자금을 인출할 수 있습니다.' % (func.name, price, setter.name))

            # 소액 상환 후 임의 차주의 담보 전체를 송금하는 경로.
            for borrower in get_address_params(contract, func):
                for ledger in uint_maps:
                    ref = re.escape(ledger) + r'\s*\[\s*' + re.escape(borrower) + r'\s*\]'
                    if re.search(ref, value_expr) and re.search(ref + r'\s*=\s*0\s*;', prefix):
                        debt_debit = re.search(r'\b(\w+)\s*\[\s*' + re.escape(borrower) + r'\s*\]\s*-=\s*(\w+)\s*;', prefix)
                        if debt_debit and debt_debit[1] != ledger and func.is_payable:
                            debt_ref = re.escape(debt_debit[1]) + r'\s*\[\s*' + re.escape(borrower) + r'\s*\]'
                            fully_repaid = any(re.search(re.escape(debt_debit[2]) + r'\s*(?:>=|==)\s*' + debt_ref + r'|' + debt_ref + r'\s*==\s*' + re.escape(debt_debit[2]), c) for _, c in prior)
                            if not fully_repaid:
                                report(send.start(), '%s()는 일부 부채를 차감한 뒤 %s의 담보 %s를 전부 0으로 만들고 호출자에게 지급합니다. 상환액과 담보 지급량의 비례 제한이 없어 소액 상환으로 전체 담보를 가져갈 수 있습니다.' % (func.name, borrower, ledger))

        # 블록 기반 값이 실제 수령자 선택에 연결된 경우만 탐지한다.
        if re.search(r'\bblock\.(?:timestamp|prevrandao|number)\b', target_expr) and 'keccak256' in target_expr:
            report(send.start(), '%s()는 블록 속성과 입력값으로 계산한 해시를 수령자 선택에 사용하고 실제 자금을 송금합니다. 결과를 예측하거나 편향시켜 상금을 가져갈 수 있는 경로입니다.' % func.name)

        # 구매자의 지급액을 기록하고 판매자 자신만의 승인으로 전액 해제.
        payee = compact(target).removeprefix('payable(').removesuffix(')')
        if privileged and payee in owner_vars and not external_guard(prefix, payee):
            for typ, escrow, _ in contract.state_vars:
                if not typ.startswith('uint') or not re.search(r'\b' + re.escape(escrow) + r'\b', value_expr):
                    continue
                for deposit in contract.functions:
                    if not deposit.is_payable or not re.search(r'\b' + re.escape(escrow) + r'\s*=\s*msg\.value\s*;', deposit.body):
                        continue
                    payer = re.search(r'\b(\w+)\s*=\s*(?:payable\s*\(\s*)?msg\.sender', deposit.body)
                    if not payer or payer[1] == payee or payer[1] not in owner_vars:
                        continue
                    consent = any('||' not in c and (
                        re.search(r'\b' + re.escape(payer[1]) + r'\s*==\s*msg\.sender|msg\.sender\s*==\s*' + re.escape(payer[1]) + r'\b', c)
                        or any(t == 'bool' and re.search(r'(?<![!\w])' + re.escape(n) + r'\b', c) for t, n, _ in contract.state_vars)) for _, c in prior)
                    if not consent:
                        report(send.start(), '%s()는 %s가 납입한 금액(%s)을 수령자 %s 본인의 권한 검사만으로 지급합니다. 구매자 확인이나 이행 승인 조건 없이 예치금을 해제할 수 있습니다.' % (func.name, payer[1], escrow, payee))

    # 직접 기부로 바뀌는 ETH 잔고를 분모로 쓰는 지분 발행.
    if func.is_payable and any(f.name == 'receive' and not f.body.strip() for f in contract.functions):
        for minted in re.finditer(r'\buint\d*\s+(\w+)\s*=\s*([^;]+);', body):
            ratio = re.search(r'msg\.value\s*\*\s*(\w+)\s*/\s*(\w+)', minted[2])
            if not ratio:
                continue
            assets = expand(ratio[2], body[:minted.start()])
            if 'address(this).balance-msg.value' not in compact(assets):
                continue
            credit = re.search(r'\b(\w+)\s*\[\s*msg\.sender\s*\]\s*\+=\s*' + re.escape(minted[1]) + r'\s*;', body[minted.end():])
            redeemable = any(re.search(r'/\s*' + re.escape(ratio[1]) + r'\b', f.body) and EXTERNAL_SEND_RE.search(f.body) for f in contract.functions)
            if credit and credit[1] in uint_maps and redeemable:
                min_shares = any(i < minted.end() + credit.start() and '||' not in c and re.search(r'\b' + re.escape(minted[1]) + r'\s*(?:>\s*0|>=\s*[1-9])', c) for i, c in conditions)
                if not min_shares:
                    report(minted.start(), '%s()는 직접 송금으로 늘어나는 계약 ETH 잔고를 분모로 지분을 내림 발행하고 0 지분을 거부하지 않습니다. 기존 지분자가 기부로 비율을 높이면 후속 입금이 0 지분으로 처리되고 기존 지분의 환매 가치에 흡수될 수 있습니다.' % func.name)




def function_flow_explanation(contract, func, newline_offsets):
    """판정과 독립적으로 실제 소스에서 권한·검사·변경·송금 근거를 추출한다.

    소스 위치순 요약은 실행 경로 증명이 아니다. 분기를 평탄화해 안전성을
    주장하지 않고, 인식한 코드와 검증된 단순 잔고 불변조건을 설명한다.
    """
    brief = lambda text: re.sub(r"\s+", " ", text).strip()
    facts = []
    for name, body in contract.modifiers.items():
        if re.search(r"\b" + re.escape(name) + r"\b", func.header):
            conditions = [brief(c) for _, c in required_conditions(body)]
            if conditions:
                facts.append("modifier %s의 검사 [%s]" % (name, "; ".join(conditions)))

    events = []
    for match in re.finditer(r"\b(require|if)\s*\(", func.body):
        end = find_matching_paren(func.body, match.end() - 1)
        args = split_top_params(func.body[match.end():end])
        if args:
            events.append((match.start(), "%s 조건 [%s]" % (match[1], brief(args[0]))))

    names = {n for _, n, _ in contract.state_vars}
    # struct storage 별칭을 통해 이루어지는 상태 변경도 근거에 포함한다.
    for match in re.finditer(r"\b\w+\s+storage\s+(\w+)\s*=\s*([^;]+);", func.body):
        names.add(match[1])
        events.append((match.start(), "storage 참조 [%s]" % brief(match[0])))
    for match in re.finditer(
            r"\b(\w+)((?:\s*\[[^;\]]+\]|\s*\.\s*\w+)*)\s*(\+=|-=|=(?!=))\s*([^;{}]+);", func.body):
        if match[1] in names:
            events.append((match.start(), "상태 변경 [%s]" % brief(match[0])))
    for match in re.finditer(
            r"(?:payable\s*\([^;{}]+?\)|msg\s*\.\s*sender|\b\w+)\s*\.\s*(?:call\s*\{[^{}]*\}|transfer\s*\([^;]+?\)|send\s*\([^;]+?\))", func.body):
        events.append((match.start(), "송금/호출 [%s]" % brief(match[0])))
        for typ, name, _ in contract.state_vars:
            if (typ.startswith("address") and "immutable" in contract.state_qualifiers.get(name, set())
                    and re.match(re.escape(name) + r"\s*\.", match[0])
                    and not re.search(r"\b" + re.escape(name) + r"\b", func_params_text(contract, func))
                    and not re.search(r"\baddress\s+(?:payable\s+)?" + re.escape(name) + r"\b", func.body)):
                facts.append("이 송금의 수령지 %s는 immutable 상태 주소이므로 호출 인자로 임의 수령지를 선택하는 경로가 아닙니다" % name)
    used_fixed = ["%s=%s" % (n, brief(init)) if init else n
                  for _, n, init in contract.state_vars
                  if contract.state_qualifiers.get(n, set()) & {"constant", "immutable"}
                  and re.search(r"\b" + re.escape(n) + r"\b", func.body)]
    if used_fixed:
        facts.append("constant/immutable 선언 [%s]" % ", ".join(used_fixed))

    if events:
        steps = ["L%d %s" % (find_line(contract, func.body_start_idx + pos, newline_offsets), text)
                 for pos, text in sorted(set(events))]
        facts.append("소스 위치순 근거: " + " → ".join(steps))

    # 단순한 최상위 검사와 동일량 차감만 안전 불변조건으로 설명한다.
    for match in re.finditer(r"\b(\w+)\s*(\[[^;\]]+\](?:\s*\[[^;\]]+\])?)\s*-=\s*(\w+)\s*;", func.body):
        if match[1] not in names:
            continue
        prefix = func.body[:match.start()]
        if prefix.count("{") != prefix.count("}"):
            continue
        ref, amount = brief(match[1] + match[2]), match[3]
        norm = lambda s: re.sub(r"\s+", "", s)
        bounded = False
        for pos, condition in required_conditions(prefix):
            if not any(norm(term) == norm(ref + ">=" + amount) for term in mandatory_terms(condition)):
                continue
            end = find_matching_paren(prefix, prefix.index("(", pos))
            between = prefix[end + 1:]
            # 중간 분기·호출·수량/장부 재대입이 있으면 불변조건을 주장하지 않는다.
            if re.search(r"[{}]|\w+\s*\(", between):
                continue
            if re.search(r"\b(?:" + re.escape(amount) + "|" + re.escape(match[1]) + r")\b[^;]*?(?:=(?!=)|\+\+|--)", between):
                continue
            bounded = True
        if bounded:
            facts.append("[%s >= %s] 검사 뒤 같은 %s를 차감하므로 확인한 %s의 한도를 소비합니다" % (ref, amount, amount, ref))
    if not facts:
        return ""
    return "%s.%s(): %s." % (contract.name, func.name, "; ".join(facts))


def benign_flow_findings(contracts, newline_offsets):
    """BENIGN에도 소스에 대응하는 근거를 제공하며 분류 결과는 바꾸지 않는다."""
    notes = []
    for contract in contracts:
        for func in ([contract.constructor] if contract.constructor else []) + contract.functions:
            explanation = function_flow_explanation(contract, func, newline_offsets)
            if explanation:
                notes.append({"malicious": False, "function": func.name,
                              "line": find_line(contract, func.header_start_idx, newline_offsets),
                              "reason": explanation, "risk_level": "LOW", "risk_type": "NONE"})
    return notes


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
        validate_delimiters(stripped)
        newline_offsets = [i for i, ch in enumerate(stripped) if ch == "\n"]
        contracts = parse_source(stripped)
    except _AnalysisTimeout:
        raise
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
    detect_analysis_gaps(stripped, newline_offsets, all_findings)
    for c in contracts:
        owner_vars = owner_like_state_vars(c)
        all_funcs = list(c.functions)
        if c.constructor:
            all_funcs = [c.constructor] + all_funcs
        for func in all_funcs:
            for detector in (
                detect_uncapped_mint, detect_transfer_asymmetry, detect_delegatecall,
                detect_fund_drain, detect_allowance_bypass, detect_reentrancy,
                detect_owner_exemption, detect_privileged_balance_mutation,
                detect_fee_siphon, detect_arbitrary_call_drain, detect_uncertain_behavior,
                detect_asset_flow_risks,
            ):
                try:
                    finding_start = len(all_findings)
                    detector(c, func, owner_vars, newline_offsets, all_findings)
                    for finding in all_findings[finding_start:]:
                        finding["flow_context"] = (c, func)
                except _AnalysisTimeout:
                    raise
                except Exception as e:
                    all_findings.append(uncertainty_finding(
                        "%s()의 %s 분석에 실패해 검사가 불완전합니다 (%s)." % (func.name, detector.__name__, type(e).__name__),
                        find_line(c, func.header_start_idx, newline_offsets), func.name))

    malicious_findings = [x for x in all_findings if x["malicious"]]
    uncertain_findings = [x for x in all_findings if x.get("uncertain")]
    benign_notes = [x for x in all_findings if not x["malicious"] and not x.get("uncertain")]

    if malicious_findings:
        verdict = "MALICIOUS"
        chosen = malicious_findings
    elif uncertain_findings:
        verdict = "UNCERTAIN"
        chosen = uncertain_findings
    elif benign_notes:
        verdict = "BENIGN"
        chosen = benign_notes
    else:
        verdict = "BENIGN"
        chosen = []

    if verdict == "BENIGN":
        chosen = chosen + benign_flow_findings(contracts, newline_offsets)
    else:
        # 위험 설명에 함수의 구체적 상태 변화와 자산 이동을 한 번씩 연결한다.
        described = set()
        for finding in chosen:
            context = finding.get("flow_context")
            if context and context not in described:
                explanation = function_flow_explanation(*context, newline_offsets)
                if explanation:
                    finding["reason"] += " " + explanation
                described.add(context)

    reasons = []
    evidence = []
    seen_reason = set()
    for fnd in chosen:
        if fnd["reason"] not in seen_reason:
            reasons.append(fnd["reason"])
            seen_reason.add(fnd["reason"])
        evidence.append({key: fnd[key] for key in ("function", "line") if key in fnd})

    if not reasons:
        reasons = ["%s: %d개 함수 본문을 검사했으며 지원하는 분석 범위에서 자산 변경·송금과 연결된 위험 근거를 발견하지 못했습니다. 인식하지 못하는 문법과 함수 간 효과에 대한 안전성 증명은 아닙니다." %
                   (", ".join(c.name for c in contracts), sum(len(c.functions) for c in contracts))]

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
        "risk_type": risk_types[0],
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
        return 1

    results = []
    deadline = time.monotonic() + TOTAL_TIMEOUT_SEC
    for fp in files:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            results.append({"file": os.path.basename(fp), "verdict": "UNCERTAIN",
                            "reasons": ["전체 분석 제한시간에 도달해 이 파일의 분석을 보류했습니다."],
                            "evidence": []})
            continue
        sys.stderr.write("[analyzer] 분석 중: %s\n" % fp)
        old_handler = None
        file_timeout = min(PER_FILE_TIMEOUT_SEC, remaining)
        if _HAS_ALARM:
            old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.setitimer(signal.ITIMER_REAL, file_timeout)
        try:
            res = analyze_file(fp)
        except _AnalysisTimeout:
            sys.stderr.write("[analyzer] 시간 초과, UNCERTAIN 처리: %s\n" % fp)
            res = {
                "file": os.path.basename(fp),
                "verdict": "UNCERTAIN",
                "reasons": ["분석 시간이 %.2f초를 초과해 이 파일만 건너뛰었습니다." % file_timeout],
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
                signal.setitimer(signal.ITIMER_REAL, 0)
                if old_handler is not None:
                    signal.signal(signal.SIGALRM, old_handler)
        results.append(coerce_to_schema(res))

    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
