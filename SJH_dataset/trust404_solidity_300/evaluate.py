#!/usr/bin/env python3
import json, sys
from collections import Counter, defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: python3 evaluate.py MODEL_OUTPUT.json")
root = Path(__file__).resolve().parent
gold = {x["file"]: x for x in json.loads((root / "answers" / "answers.json").read_text())}
raw = json.loads(Path(sys.argv[1]).read_text())
if not isinstance(raw, list) or not raw:
    raise SystemExit("model output must be a non-empty JSON array")
pred = {}
for row in raw:
    if isinstance(row, dict) and row.get("file") in gold and row.get("file") not in pred:
        pred[row["file"]] = row.get("verdict", "UNCERTAIN")
valid = {"MALICIOUS", "BENIGN", "UNCERTAIN"}
matrix = defaultdict(Counter)
correct = wrong = abstain = 0
by_category = defaultdict(lambda: Counter(total=0, correct=0, wrong=0, uncertain=0))
for name, truth in gold.items():
    guess = pred.get(name, "UNCERTAIN")
    if guess not in valid: guess = "UNCERTAIN"
    actual = truth["verdict"]
    matrix[actual][guess] += 1
    bucket = by_category[truth["category"]]; bucket["total"] += 1
    if guess == "UNCERTAIN": abstain += 1; bucket["uncertain"] += 1
    elif guess == actual: correct += 1; bucket["correct"] += 1
    else: wrong += 1; bucket["wrong"] += 1
decided = correct + wrong
report = {
    "total": len(gold), "correct": correct, "wrong": wrong, "uncertain": abstain,
    "coverage": decided / len(gold), "decided_accuracy": (correct / decided if decided else None),
    "net_score": max(0, correct - wrong),
    "confusion_matrix": {a: dict(matrix[a]) for a in sorted(matrix)},
    "by_category": {k: dict(v) for k, v in sorted(by_category.items())},
}
print(json.dumps(report, ensure_ascii=False, indent=2))
