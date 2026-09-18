#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
schema.json (draft 2020-12) 의 요건을 표준 라이브러리만으로 직접 재현해 검증한다.
check-jsonschema 등 외부 패키지가 없는 오프라인 환경에서도 제출 전 자가 점검이
가능하도록 만든 보조 스크립트다. (자동 채점 파이프라인의 일부가 아님)

사용법: python3 validate_schema.py out.json input_dir/
"""
import sys
import json
import os
import re

FILE_RE = re.compile(r"^[^/\\\r\n]+\.sol$")
VERDICTS = {"MALICIOUS", "BENIGN", "UNCERTAIN"}
RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
RISK_TYPES = {"BACKDOOR", "VULNERABILITY", "CENTRALIZATION", "NONE"}


def validate_item(item, idx, errors):
    prefix = "item[%d]" % idx
    if not isinstance(item, dict):
        errors.append("%s: 객체가 아닙니다" % prefix)
        return
    for req in ("file", "verdict", "reasons", "evidence"):
        if req not in item:
            errors.append("%s: 필수 필드 '%s' 누락" % (prefix, req))
    if "file" in item:
        if not isinstance(item["file"], str) or not FILE_RE.match(item["file"]):
            errors.append("%s: file 형식 위반 (%r)" % (prefix, item.get("file")))
    if "verdict" in item and item["verdict"] not in VERDICTS:
        errors.append("%s: verdict 값 위반 (%r)" % (prefix, item.get("verdict")))
    if "reasons" in item:
        if not isinstance(item["reasons"], list) or not all(isinstance(r, str) and r for r in item["reasons"]):
            errors.append("%s: reasons 형식 위반" % prefix)
    if "evidence" in item:
        if not isinstance(item["evidence"], list):
            errors.append("%s: evidence 형식 위반" % prefix)
        else:
            for ei, e in enumerate(item["evidence"]):
                if not isinstance(e, dict) or not ("function" in e or "line" in e):
                    errors.append("%s.evidence[%d]: function/line 중 하나 이상 필요" % (prefix, ei))
                if "line" in e and (not isinstance(e["line"], int) or e["line"] < 1):
                    errors.append("%s.evidence[%d]: line은 1 이상의 정수여야 함" % (prefix, ei))
        if item.get("verdict") == "MALICIOUS" and not item.get("evidence"):
            errors.append("%s: verdict=MALICIOUS 인데 evidence가 비어 있음" % prefix)
    if "risk_level" in item and item["risk_level"] not in RISK_LEVELS:
        errors.append("%s: risk_level 값 위반" % prefix)
    if "risk_type" in item and item["risk_type"] not in RISK_TYPES:
        errors.append("%s: risk_type 값 위반" % prefix)
    if "confidence" in item:
        c = item["confidence"]
        if not isinstance(c, (int, float)) or c < 0.0 or c > 1.0:
            errors.append("%s: confidence 범위 위반" % prefix)


def main():
    if len(sys.argv) < 2:
        print("usage: validate_schema.py <output.json> [input_dir]", file=sys.stderr)
        return 1
    out_path = sys.argv[1]
    input_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with open(out_path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        data = json.loads(raw)
    except Exception as e:
        print("FAIL: stdout이 유효한 JSON이 아닙니다: %s" % e)
        return 1

    if not isinstance(data, list):
        print("FAIL: 최상위 값이 배열이 아닙니다")
        return 1
    if len(data) == 0:
        print("FAIL: 빈 배열입니다 (minItems: 1 위반)")
        return 1

    errors = []
    seen_files = set()
    for idx, item in enumerate(data):
        validate_item(item, idx, errors)
        f = item.get("file") if isinstance(item, dict) else None
        if f:
            if f in seen_files:
                print("INFO: 중복 file '%s' - 채점기는 처음 것만 사용" % f)
            seen_files.add(f)

    if input_dir:
        input_files = {n for n in os.listdir(input_dir) if n.lower().endswith(".sol")}
        missing = input_files - seen_files
        extra = seen_files - input_files
        for m in missing:
            print("INFO: 입력에 있었지만 출력에 없는 파일 -> UNCERTAIN 처리됨: %s" % m)
        for e in extra:
            print("INFO: 출력에만 있는 파일(무시됨): %s" % e)

    if errors:
        print("FAIL: %d개 스키마 위반 발견" % len(errors))
        for e in errors:
            print(" -", e)
        return 1

    print("OK: %d개 항목 모두 schema.json 요건을 통과했습니다" % len(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
