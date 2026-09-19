# TRUST404 Track 1 제출물 — 규칙 기반 Solidity 위협 탐지기

## 개요
`.sol` 소스를 정적으로 분석해 `MALICIOUS` / `BENIGN` / `UNCERTAIN` 을 판정하는
오프라인 CLI 도구입니다. 외부 API·LLM 호출이나 인터넷 접속 없이, Python 표준
라이브러리만으로 컨트랙트의 함수·모디파이어·상태변수를 파싱하고, 권한 구조와
로직 흐름을 보는 규칙(rule)을 적용합니다.

## 실행 방법

```bash
./run.sh <디렉터리>
```

예:
```bash
./run.sh ./challenge_public > out.json
```

- 입력: 디렉터리 경로. 그 디렉터리 바로 아래의 `*.sol` 전부를 한 번의 호출로 처리합니다.
  단일 `.sol` 파일 경로도 편의상 지원합니다 (`./run.sh ./P4_CappedMint.sol`).
- 출력: `schema.json` 을 준수하는 JSON 배열을 **stdout 에만** 출력합니다.
  진행 로그는 전부 stderr 로 갑니다.
- 종속성: Python 3 (표준 라이브러리만 사용, `pip install` 불필요). `python3` 이
  없으면 `python` 을 사용합니다.
- 시간: 파일 하나가 20초를 넘기면(`TRUST404_PER_FILE_TIMEOUT` 환경변수로 조정 가능)
  그 파일만 `UNCERTAIN` 처리하고 다음 파일로 넘어갑니다 (SIGALRM 기반, Unix 전제).
- 실패 처리: 파싱 실패, contract 정의를 찾지 못한 경우, 예외 발생 등은 모두 해당
  파일만 `UNCERTAIN` 으로 출력하고 나머지 파일 처리를 계속합니다.

### 제출 전 스키마 자가 검증 (선택)
```bash
./run.sh ./challenge_public > out.json
python3 validate_schema.py out.json ./challenge_public
```
`check-jsonschema` 같은 외부 패키지가 없는 환경에서도 `schema.json` 의 핵심 요건
(필수 필드, verdict enum, MALICIOUS ⇒ evidence 비어있지 않음, file 패턴 등)을
표준 라이브러리만으로 재현해 검증합니다. 자동 채점 파이프라인의 일부는 아니며
개발/제출 전 점검용입니다.

## 판정 로직

키워드 매칭이 아니라 각 함수의 **호출 권한(누가 부를 수 있는가)** 과
**상태 변화(무엇을 바꾸는가)** 를 연결해서 본다는 원칙으로 아래 네 가지 탐지
규칙을 둡니다.

| 규칙 | 판단 기준 |
|---|---|
| **상한 없는 발행 (Uncapped mint)** | `totalSupply` 를 증가시키는 함수를 찾고, 증가 이전 구간에 `<= cap` / `<= MAX_SUPPLY` 류의 상한 검사가 있는지 확인합니다. 상한이 있으면 `BENIGN`(중앙화 위험만 부기), 없으면 — 호출 권한이 있든 없든 — `MALICIOUS` 입니다. P2 vs P4 구분과 동일한 기준입니다. |
| **가변 상한 (Moving cap) / 검사·효과 불일치** | 상한이 있어도 (a) 그 상한 변수가 `constant`/`immutable` 이 아니고 소유자가 별도 검증 없이 자유롭게 올릴 수 있으면, 또는 (b) 검사에 쓰인 변수와 실제로 `totalSupply`에 더해지는 값이 다르면(예: 검사는 `amount`, 실제 증가는 `amount * 10`) — 상한이 있는 것처럼 보여도 사실상 무제한 발행이므로 `MALICIOUS` 입니다. |
| **비대칭 전송 제한 (Honeypot)** | `transfer`/`transferFrom` 류 함수에서 전송 가능 여부를 결정하는 조건을 찾습니다. 그 조건이 **모든 주소에 동일하게 적용되는 전역 플래그**(예: `paused`)면 대칭 제약으로 `BENIGN`(가용성 제약일 뿐 자산 이전 경로가 아님). 반면 조건이 **`msg.sender` 별로 값이 다른 매핑**이고 그 매핑을 소유자만 바꿀 수 있거나, 전역 플래그라도 `msg.sender == owner` 류로 소유자만 예외 처리되어 있으면 비대칭 구조로 `MALICIOUS` 입니다. |
| **승인(allowance) 우회** | `transferFrom()` 이 `allowance[from][msg.sender]` 를 아예 검사하지 않거나, 검사만 하고 차감하지 않으면 — 승인 없이 전송하거나 같은 승인 한도를 여러 번 재사용해 초과 전송이 가능하므로 `MALICIOUS` 입니다. |
| **소유자만 예외 (Owner exemption)** | 함수·변수 이름과 무관하게, `if (msg.sender != owner) { ... }` 또는 `require(조건 \|\| msg.sender == owner)` 처럼 **다른 사용자에게는 적용되는 검사를 소유자만 건너뛰는 코드 구조** 자체를 찾습니다. 그 함수가 잔고·승인·전송가능여부 같은 자산 관련 매핑을 실제로 건드릴 때만 `MALICIOUS`로 보고해 오탐을 줄입니다. |
| **임의 잔고 조작 (Arbitrary balance mutation)** | `seize()`, `maintenance()`, `ownerBurn()` 류처럼 승인(allowance) 절차 없이 **함수 파라미터로 받은 임의 계정**의 balance 매핑을 직접 덮어쓰거나(`=`) 차감하는(`-=`) 특권 함수를 찾습니다. `transferFrom()`처럼 정상적인 allowance 검증이 함께 있으면 제외합니다. |
| **수수료 갈취 (Fee siphon)** | `transfer()` 안에서 전송액의 일부를 소유자 잔고로 적립하는 수수료 로직 중, 그 수수료율 변수를 소유자가 상한 검증 없이(또는 사실상 100%까지) 설정할 수 있으면 `MALICIOUS` 입니다. |
| **재진입 (Reentrancy)** | 인출류 함수에서 `msg.sender` 잔고를 확인하는 `require` 이후 외부 전송(`.call{value:}`, `.transfer`, `.send`)이 실행되는데, 그 잔고를 차감하는 코드가 전송 **이후**에 있거나 아예 없으면 checks-effects-interactions 위반으로 `MALICIOUS` 입니다. 차감이 전송보다 먼저 있으면 `BENIGN` 입니다. |
| **Delegatecall 백도어** | 고수준 `.delegatecall(...)` 뿐 아니라 **인라인 어셈블리의 `delegatecall(gas(), target, ...)`** 형태도 인식합니다. 대상이 생성자에서 한 번만 고정된 `immutable` 주소(세터 없음, 함수 파라미터도 아님)면 프록시 패턴으로 보고 `BENIGN`(낮은 위험으로 부기). 그 외 — 함수 파라미터로 받은 주소, 세터가 있는 가변 상태변수 등 — 는 스토리지 문맥을 공유하는 임의 코드 실행 경로이므로 `MALICIOUS` 입니다. |
| **예치금 우회 인출 (Fund drain)** | `deposit`류 payable 함수가 사용자별 매핑(`deposits`, `stake` 등)에 잔고를 기록하는 컨트랙트에서, 별도 함수가 그 매핑 회계를 거치지 않고 `address(this).balance` 전체를 이동시키거나 `selfdestruct` 하면 사용자 예치금 탈취 경로로 보아 `MALICIOUS`. 그런 예치 매핑이 애초에 없는 컨트랙트에서 소유자가 잔고를 회수하는 것은 강제 송금된 ETH 회수로 보아 `BENIGN` 입니다 (README의 자산 귀속 가정 3번). |

10가지 규칙 모두에서 발견되지 않으면 `BENIGN` 이며, 컨트랙트 정의 자체를 인식하지
못했거나(파싱 실패 등) 판단에 필요한 근거를 특정하지 못하면 `UNCERTAIN` 으로
안전하게 하향합니다 (예: `MALICIOUS` 로 분류될 뻔했지만 위치 근거가 없어 스키마
요건을 만족 못하는 경우).

## 공개 샘플 결과 (캘리브레이션)

| 파일 | 라벨 | 본 도구의 판정 |
|---|---|---|
| P1_StandardToken | BENIGN | BENIGN |
| P2_HiddenMint | MALICIOUS | MALICIOUS (`distributeRewards`, line 31) |
| P3_Honeypot | MALICIOUS | MALICIOUS (`transfer`, line 37) |
| P4_CappedMint | BENIGN | BENIGN (`mint`, line 27 — 상한 검사 확인) |
| P5_DelegatecallBackdoor | MALICIOUS | MALICIOUS (`execute`, line 37) |

5종 모두 라벨과 일치합니다. `variants/` 에는 자체 제작한 6종의 추가 검증용
변형(대칭 pause / 소유자 예외 pause / 권한 없는 공개 민팅 / 예치금 우회 인출 /
비예치 컨트랙트의 잔고 회수 / 불변 프록시 delegatecall)을, `variants2/` 에는
가변 상한·검사-효과 불일치·승인 우회·재진입 규칙을 검증하는 7종(각 규칙의
위험/안전 쌍)을 두어 하드코딩이 아닌 로직 기반 판별이 P1~P5 이외의 패턴에도
일반화되는지 확인했습니다.

| 파일 | 기대 | 판정 |
|---|---|---|
| W1_MutableCapRisk | MALICIOUS | MALICIOUS — 상한 변수를 소유자가 무검증으로 올릴 수 있음 |
| W2_MutableCapSafe | BENIGN | BENIGN — 상한 변경에 자체 상한(ABSOLUTE_MAX) 검증 있음 |
| W3_AmountMismatchRisk | MALICIOUS | MALICIOUS — 검사는 `amount`, 실제 증가는 `amount * 10` |
| W4_AllowanceNoDecrementRisk | MALICIOUS | MALICIOUS — 승인 검사만 하고 차감 안 함 |
| W5_AllowanceSafe | BENIGN | BENIGN — 검사 후 정상적으로 차감 |
| W6_ReentrancyRisk | MALICIOUS | MALICIOUS — 잔고 차감 전에 외부 전송 실행 |
| W7_ReentrancySafe | BENIGN | BENIGN — 외부 전송 전에 잔고 먼저 차감 |

## 독립 제작 40케이스 검증 (GPT로 생성한 practice dataset)

저희가 만들지 않은, 별도로 GPT에게 생성을 요청한 30개 신규 샘플(`gpt_dataset/` — BENIGN 10 ·
MALICIOUS 10 · UNCERTAIN 10, 정답 라벨은 `gpt_dataset/manifest.json`)로 교차 검증했습니다.

| 구간 | 결과 |
|---|---|
| BENIGN 10종 | 10/10 일치 |
| MALICIOUS 10종 | 10/10 일치 (최초 시도에서 7종을 놓쳐 규칙 3개를 새로 추가한 뒤 전부 일치) |
| UNCERTAIN 10종 | 참고용 — 아래 설명 참고 |

이 데이터셋 덕분에 발견하고 고친 실제 버그:
- **소유자 예외가 `if (msg.sender != owner) { require(조건); ... }` 처럼 조건문으로 감싸져 있으면** 기존 정규식이 놓쳤음 → 함수 이름·매핑 이름과 무관하게 "소유자만 예외" 코드 구조 자체를 잡는 규칙(`detect_owner_exemption`)을 추가
- **`require(!blocked[msg.sender] && !blocked[to])` 처럼 `&&`/`\|\|` 로 여러 조건이 묶이면** 기존 정규식이 첫 조건만 보고 놓쳤음 → 조건식 전체를 캡처하도록 재작성
- **`seize()`/`maintenance()`/`ownerBurn()` 처럼 mint·transfer·delegatecall·selfdestruct 어디에도 해당하지 않는, 임의 계정의 잔고를 직접 덮어쓰거나 차감하는 특권 함수**는 아예 탐지 규칙이 없었음 → 신규 규칙 추가
- **owner에게 전송액의 일부를 상한 없이 떼어주는 수수료(tax) 로직**도 탐지 규칙이 없었음 → 신규 규칙 추가
- **인라인 어셈블리로 작성된 `delegatecall(gas(), impl, ...)`** 은 고수준 `.delegatecall(...)` 정규식과 문법이 달라 완전히 놓치고 있었음 → 별도 패턴 추가

**UNCERTAIN 10종에 대한 설계 판단**: 이 저장소의 분석기는 파싱 실패 상황에서만 `UNCERTAIN`을
내고, "코드만으로는 의도를 판단하기 어렵다"는 의미의 `UNCERTAIN`은 자체적으로 판단하지 않습니다.
그래서 이 10종에는 대부분 `BENIGN` 또는 `MALICIOUS` 중 하나로 확정적인 답을 냅니다. 이는 의도적인
선택입니다 — 대회 README가 정의한 경계 규칙(예: 대칭/비대칭 제약, 상한 유무)은 "업계 관행일 수도
있다"는 여지를 별도로 두지 않고 구조로 확정하도록 되어 있고, 실제로 공식 샘플 `P3_Honeypot`도
"규제 준수용일 수도 있는" 화이트리스트 구조를 망설임 없이 `MALICIOUS`로 규정합니다. 다만 두 파일은
분석기가 놓치고 있던 실제 버그라 함께 고쳤습니다(`U03_ComplianceBlacklist`, `U10_AdminTransferExemption`
모두 소유자 예외 규칙에 걸려 이제 `MALICIOUS`로 나옵니다). 나머지(외부 오라클 의존, 임의 컨트랙트 호출
지갑, 역할 기반 스윕 등)는 "이 컨트랙트의 역할을 모르면 원천적으로 답할 수 없는" 성격이 강해 규칙을
추가하지 않고 `BENIGN`으로 남겨뒀습니다 — 채점 규칙상 UNCERTAIN은 항상 0점이므로, 이 부분에서
확신 없이 무리하게 새 규칙을 추가해 다른 파일에 오탐을 만드는 위험을 지지 않기로 판단했습니다.

## 알려진 한계
- 정규식·괄호 매칭 기반 경량 파서이며 완전한 Solidity 문법 파서(예: `solc` AST)는
  아닙니다. 매우 복잡한 중첩 구조나 비표준적인 포맷팅에서는 함수/모디파이어 경계
  인식이 실패할 수 있으며, 그 경우 해당 파일은 안전하게 `UNCERTAIN` 으로
  떨어집니다 (오답 감점보다 무득점을 택함).
- 상속(`is`)으로 여러 컨트랙트에 로직이 분산된 경우, 부모 컨트랙트의 모디파이어나
  상태변수까지는 추적하지 않고 파일 내 각 컨트랙트를 독립적으로 봅니다.
- `import` 가 있는 멀티파일 컨트랙트는 가정하지 않습니다 (공개 샘플과 동일하게
  단일 파일 자기완결을 전제).
- 재진입 탐지는 "인출류 함수 안에서 외부 전송과 잔고 차감의 순서"라는 단일 패턴만
  봅니다. 루프, 별도 헬퍼 함수 호출, 재진입 가드(`nonReentrant`) 등을 통한 더
  복잡한 흐름은 인식하지 못할 수 있습니다.

## 파일 구성
```
run.sh              # 비대화형 진입점
analyzer.py         # 파서 + 탐지 규칙 + CLI 본체 (표준 라이브러리만 사용)
validate_schema.py  # 제출 전 자가 스키마 검증 (선택, 채점 파이프라인 외부)
schema.json          # 출제측 제공 스키마 원본 (검증용으로 동봉)
challenge_public/    # 공개 샘플 5종 (캘리브레이션 확인용, 채점에는 비공개셋 사용)
variants/            # 자체 제작 추가 검증용 변형 6종
variants2/           # 가변 상한/증가량 불일치/승인 우회/재진입 검증용 변형 7종
gpt_dataset/         # 별도로 GPT에게 생성 요청한 독립 검증용 30종 + 정답(manifest.json)
```
