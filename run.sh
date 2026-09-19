#!/usr/bin/env bash
# TRUST404 Track 1 비대화형 진입점
# 사용법: ./run.sh <.sol 파일들이 있는 디렉터리>
# stdout: 채점용 JSON 배열만 출력
# stderr: 진행 로그
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <directory-or-file>" >&2
  exit 1
fi

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi

exec "$PY" "$SCRIPT_DIR/analyzer.py" "$1"
