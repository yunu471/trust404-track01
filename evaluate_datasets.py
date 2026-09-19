"""현재 CLI를 두 로컬 데이터셋에 실행하고 판별 점수·출력 무결성을 기록한다.

이유 타당성 0/1/2점은 자동 부여하지 않는다. GPT 정답은 파일명 기반 가정이다.
"""
import collections
import hashlib
import json
import pathlib
import subprocess
import time

from validate_schema import validate_item

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / 'evaluation_results'


def evaluate(name, directory, labels, label_source):
    started = time.monotonic()
    process = subprocess.run(['bash', str(ROOT / 'run.sh'), str(directory)],
                             capture_output=True, text=True, timeout=590)
    elapsed = time.monotonic() - started
    (OUT / (name + '_verified_predictions.json')).write_text(process.stdout, encoding='utf-8')
    (OUT / (name + '_verified_analysis.log')).write_text(process.stderr, encoding='utf-8')
    rows = json.loads(process.stdout)
    if not isinstance(rows, list) or not rows:
        raise ValueError('stdout must be a nonempty JSON array')
    files = {p.name: p for p in directory.glob('*.sol')}
    if set(files) != set(labels):
        raise ValueError('input files and labels differ')
    predictions, errors, line_errors, duplicates, extras = {}, [], [], [], []
    for index, row in enumerate(rows):
        item_errors = []
        validate_item(row, index, item_errors)
        errors.extend(item_errors)
        filename = row.get('file')
        if filename not in files:
            extras.append(filename)
            continue
        if filename in predictions:
            duplicates.append(filename)
            continue
        predictions[filename] = 'UNCERTAIN' if item_errors else row['verdict']
        line_count = len(files[filename].read_text(encoding='utf-8').splitlines())
        for evidence in row.get('evidence', []):
            if 'line' in evidence and not 1 <= evidence['line'] <= line_count:
                line_errors.append({'file': filename, 'evidence': evidence})
    matrix = collections.defaultdict(collections.Counter)
    counts = collections.Counter(correct=0, wrong=0, uncertain=0)
    mismatches, abstentions = [], []
    for filename, actual in sorted(labels.items()):
        guess = predictions.get(filename, 'UNCERTAIN')
        matrix[actual][guess] += 1
        result = 'uncertain' if guess == 'UNCERTAIN' else 'correct' if guess == actual else 'wrong'
        counts[result] += 1
        if result == 'wrong':
            mismatches.append({'file': filename, 'expected': actual, 'predicted': guess})
        if result == 'uncertain':
            abstentions.append({'file': filename, 'expected': actual})
    total = len(files)
    net = max(0, counts['correct'] - counts['wrong'])
    decided = counts['correct'] + counts['wrong']
    report = {
        'dataset': name, 'label_source': label_source,
        'analyzer_sha256': hashlib.sha256((ROOT / 'analyzer.py').read_bytes()).hexdigest(),
        'exit_code': process.returncode, 'elapsed_seconds': round(elapsed, 3),
        'total': total, **counts, 'net_score': net,
        'linear_normalized_10_assumption': net / total * 10,
        'linear_converted_15_assumption': net / total * 15,
        'coverage': decided / total,
        'decided_accuracy': counts['correct'] / decided if decided else None,
        'confusion_matrix': dict(matrix), 'mismatches': mismatches,
        'abstentions': abstentions,
        'validation': {'method': 'standard-library schema core checks, not full Draft 2020-12',
                       'errors': errors, 'missing': sorted(set(files) - set(predictions)),
                       'duplicates': duplicates, 'extras': extras, 'line_errors': line_errors,
                       'empty_reasons': sum(not row.get('reasons') for row in rows),
                       'empty_evidence': sum(not row.get('evidence') for row in rows),
                       'detector_failures': sum(any('분석에 실패' in r for r in row['reasons']) for row in rows)},
        'reason_validity_score': None,
        'reason_validity_note': 'Requires manual code/reason review; evidence presence does not imply 2 points.',
    }
    (OUT / (name + '_verified_score.json')).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ['dataset', 'total', 'correct', 'wrong', 'uncertain',
                                           'net_score', 'elapsed_seconds', 'confusion_matrix', 'validation']},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    OUT.mkdir(exist_ok=True)
    gpt = ROOT / 'gpt_dataset'
    label_map = {'B': 'BENIGN', 'M': 'MALICIOUS', 'U': 'UNCERTAIN'}
    evaluate('gpt', gpt, {p.name: label_map[p.name[0]] for p in gpt.glob('*.sol')},
             'Filename B/M/U proxy only; not an authoritative answer key')
    sjh = ROOT / 'SJH_dataset/trust404_solidity_300'
    gold = json.loads((sjh / 'answers/answers.json').read_text(encoding='utf-8'))
    evaluate('sjh', sjh / 'cases', {row['file']: row['verdict'] for row in gold},
             'SJH_dataset/trust404_solidity_300/answers/answers.json')
