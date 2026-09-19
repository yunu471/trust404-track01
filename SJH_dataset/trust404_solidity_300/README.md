# TRUST404 Solidity Evaluation Corpus — 300 cases

이 자료는 TRUST404 Track 1의 `MALICIOUS / BENIGN / UNCERTAIN` 판별기를 블라인드 평가하기 위한 **합성·축약 코퍼스**입니다.

## 구성

- 총 300개 독립 `.sol` 파일
- MALICIOUS 120개 / BENIGN 120개 / UNCERTAIN 60개
- 24개 의미 패턴군, 패턴군당 12~13개 변주
- Solidity `^0.8.20`
- 파일명·컨트랙트명·주석에 정답 또는 패턴명을 넣지 않음
- 실제 운영 컨트랙트나 공격 코드를 복사하지 않고 공개 취약점의 **근본 원리만 최소 예제로 재구성**

## 디렉터리

- `cases/`: 모델에 입력할 300개 Solidity 파일
- `answers/answers.json`: Track 1 스키마 호환 정답과 근거
- `answers/answers.csv`: 사람이 빠르게 검토할 수 있는 표
- `schema.json`: 대회 출력 스키마 사본
- `evaluate.py`: 모델 출력 평가기
- `SOURCES.md`: 설계 근거와 공개 참고자료
- `manifest_sha256.txt`: 파일 무결성 목록

`answers/`를 모델 입력 디렉터리와 반드시 분리하세요. 각 파일에는 정답 힌트가 없지만 정답 파일의 `category`는 패턴군을 공개합니다.

## 평가

```bash
python3 evaluate.py model_output.json
```

평가기 출력에는 정답 수, 오답 수, UNCERTAIN 수, coverage, 확정 판정 accuracy, 대회식 net score(+1/0/-1), confusion matrix가 포함됩니다.

## 라벨 원칙

- `MALICIOUS`: 의도 단정이 아니라 배포 전 차단·경고해야 할 자산 손실, 권한 남용, 비대칭 제한 경로
- `BENIGN`: 위험 키워드가 있어도 Track 1 경계상 자산 탈취·러그 경로가 없는 사례
- `UNCERTAIN`: 외부 정책·오라클·권한·회계 모듈 구현이 없으면 확정할 수 없는 사례

## 중요한 제한

이 코드는 교육·평가용 최소 예제이며 운영 배포용이 아닙니다. `BENIGN`은 Track 1의 판정 기준에서의 정답이지 완전한 제품 수준 감사 보증이 아닙니다. 공개 버그바운티 자료는 취약 원리와 경계 사례 선정에만 사용했으며 원문 코드를 복제하지 않았습니다.
