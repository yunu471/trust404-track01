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
| **비대칭 전송 제한 (Honeypot)** | `transfer`/`transferFrom` 류 함수에서 전송 가능 여부를 결정하는 조건을 찾습니다. 그 조건이 **모든 주소에 동일하게 적용되는 전역 플래그**(예: `paused`)면 대칭 제약으로 `BENIGN`(가용성 제약일 뿐 자산 이전 경로가 아님). 단, 기본 허용 상태에서 송신자·수신자 양쪽에 같은 차단 정책을 적용하는 경우는 운영 의도를 확정할 수 없어 `UNCERTAIN`입니다. 그 외 조건이 **`msg.sender` 별로 값이 다른 매핑**이고 그 매핑을 소유자만 바꿀 수 있거나, 전역 플래그라도 `msg.sender == owner` 류로 소유자만 예외 처리되어 있으면 비대칭 구조로 `MALICIOUS` 입니다. |
| **승인(allowance) 우회** | `transferFrom()` 이 `allowance[from][msg.sender]` 를 아예 검사하지 않거나, 검사만 하고 차감하지 않으면 — 승인 없이 전송하거나 같은 승인 한도를 여러 번 재사용해 초과 전송이 가능하므로 `MALICIOUS` 입니다. |
| **소유자만 예외 (Owner exemption)** | 함수·변수 이름과 무관하게, `if (msg.sender != owner) { ... }` 또는 `require(조건 \|\| msg.sender == owner)` 처럼 **다른 사용자에게는 적용되는 검사를 소유자만 건너뛰는 코드 구조** 자체를 찾습니다. 그 함수가 잔고·승인·전송가능여부 같은 자산 관련 매핑을 실제로 건드릴 때만 `MALICIOUS`로 보고해 오탐을 줄입니다. |
| **임의 잔고 조작 (Arbitrary balance mutation)** | `seize()`, `maintenance()`, `ownerBurn()` 류처럼 승인(allowance) 절차 없이 **함수 파라미터로 받은 임의 계정**의 balance 매핑을 직접 덮어쓰거나(`=`) 차감하는(`-=`) 특권 함수를 찾습니다. `transferFrom()`처럼 정상적인 allowance 검증이 함께 있으면 제외합니다. |
| **수수료 갈취 (Fee siphon)** | `transfer()` 안에서 전송액의 일부를 소유자 잔고로 적립하는 수수료 로직 중, 그 수수료율 변수를 소유자가 상한 검증 없이(또는 사실상 100%까지) 설정할 수 있으면 `MALICIOUS` 입니다. |
| **재진입 (Reentrancy)** | 인출류 함수에서 `msg.sender` 잔고를 확인하는 `require` 이후 외부 전송(`.call{value:}`, `.transfer`, `.send`)이 실행되는데, 그 잔고를 차감하는 코드가 전송 **이후**에 있거나 아예 없으면 checks-effects-interactions 위반으로 `MALICIOUS` 입니다. 차감이 전송보다 먼저 있으면 `BENIGN` 입니다. |
| **Delegatecall 백도어** | 고수준 `.delegatecall(...)` 뿐 아니라 **인라인 어셈블리의 `delegatecall(gas(), target, ...)`** 형태도 인식합니다. 대상이 생성자에서 한 번만 고정된 `immutable` 주소(세터 없음, 함수 파라미터도 아님)면 외부 구현의 안전성을 확인할 수 없어 `UNCERTAIN`. 관리자만 변경 가능한 상태 주소로 fallback이 위임하고 자체 매핑 회계가 없는 프록시는 구현·업그레이드 정책 확인이 필요해 `UNCERTAIN`입니다. 그 외 — 함수 파라미터로 받은 주소, 세터가 있는 가변 상태변수 등 — 는 스토리지 문맥을 공유하는 임의 코드 실행 경로이므로 `MALICIOUS` 입니다. |
| **예치금 우회 인출 (Fund drain)** | `deposit`류 payable 함수가 사용자별 매핑(`deposits`, `stake` 등)에 잔고를 기록하는 컨트랙트에서, 별도 함수가 그 매핑 회계를 거치지 않고 `address(this).balance` 전체를 이동시키거나 `selfdestruct` 하면 사용자 예치금 탈취 경로로 보아 `MALICIOUS`. 장부 없이 누구나 ETH를 보낼 수 있는 receive가 있고 관리자만 송금할 수 있으면 자금 귀속을 몰라 `UNCERTAIN`입니다. 그 외 예치 매핑이 애초에 없는 컨트랙트에서 소유자가 잔고를 회수하는 것은 강제 송금된 ETH 회수로 보아 `BENIGN` 입니다 (README의 자산 귀속 가정 3번). |
| **임의 대상·금액 호출 (Arbitrary call drain)** | `route(target, value, data)` 처럼 대상과 금액을 함수 인자로 받아 저수준 `.call{value: value}(...)` 을 실행하는 특권 함수를 찾습니다. `address(this).balance` 라는 리터럴이 없어도, 컨트랙트에 예치 장부가 있으면 예치금을 임의 주소로 빼돌리는 경로이므로 `MALICIOUS` 입니다. |

판정 우선순위는 **MALICIOUS → UNCERTAIN → BENIGN** 입니다.

- `MALICIOUS`: 기존 탐지 규칙에서 악성 근거를 발견한 경우. 불확실한 경로가 함께 있어도 악성 판정을 우선합니다.
- `UNCERTAIN`: 악성 근거는 없지만 외부 구현이나 분석 범위의 한계 때문에 안전성을 확정할 수 없는 경우.
  외부 오라클·검증 훅·토큰 메서드 호출, 데이터가 있는 저수준 호출, 고정 대상 delegatecall,
  관리자 변경이 가능한 예치금 시간·중단 제약, import·상속·어셈블리가 해당합니다.
  또한 송·수신자 양쪽 차단 정책, 공개 ETH 수신 후 관리자 회수, 관리자 업그레이드 프록시는
  운영 정책이나 자금 귀속을 확인할 수 없어 `UNCERTAIN`으로 다룹니다.
  근거와 해당 코드 위치를 함께 출력합니다. 단순 ETH 송금과 ABI 인코딩 자체는 이 규칙의 대상이 아닙니다.
- `BENIGN`: 악성 근거와 위 불확실성 신호가 모두 없는 경우. 지원하는 규칙 범위 내의 판정이며 안전성 증명은 아닙니다.

파일 읽기·파싱 실패, 닫히지 않은 괄호·주석·문자열, 시간 초과도 `UNCERTAIN`으로 처리합니다.
개별 탐지 규칙이 실패하면 검사가 불완전하다는 근거를 기록하고 나머지 규칙을 계속 실행합니다.
`UNCERTAIN`의 `MEDIUM` 위험 등급은 검토 필요성을 나타내며 악성 확률을 뜻하지 않습니다.

회귀 테스트: `python3 -m unittest -v test_analyzer`

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

## 300케이스 확장 검증 (2차)

이후 같은 방식으로 300개(B/M/U 각 100개)로 확장한 배치에서 아래 4개 버그를 추가로 찾아 고쳤습니다.
정답 라벨 없이 파일명 규칙(B=BENIGN, M=MALICIOUS 기대)만으로 채점한 결과, B는 100/100, M은
100/100 (수정 전 각각 94/100, 82/100) 까지 끌어올렸습니다.

| 버그 | 증상 | 원인 | 수정 |
|---|---|---|---|
| `burnAllowance` 미인식 | 정상적으로 승인·차감하는 `burnFrom()`을 오탐(MALICIOUS)으로 잘못 판정 | 승인 매핑 이름이 정확히 `allowance`인지만 대소문자 구분해서 검사 | `\w*allow\w*` 로 대소문자 무시하고 폭넓게 매칭 |
| 이름 없는 게이트 매핑 | `permitted`처럼 화이트리스트류 키워드 목록에 없는 이름은 놓침 | `whitelist/blacklist/...` 고정 키워드 목록에만 의존 | 이름 대신 "owner만 바꿀 수 있는 `mapping(address=>bool)`로 전송을 통제하는가" 구조로 판단 |
| 세터 없는 고정 고율 수수료 | `taxBps = 9900`(생성 시 99% 고정, 세터 없음)를 그냥 통과시킴 | "세터로 올릴 수 있는 상한"만 보고, 세터가 없으면 검사 자체를 건너뜀 | 세터가 없으면 초기값 자체를 검사하도록 보완 |
| 파라미터 기반 임의 외부 호출 | `route(target, value, data)` 처럼 `value`를 함수 인자로 받는 임의 호출은 놓침 | 기존 자금 인출 탐지가 `address(this).balance` 라는 리터럴 문자열만 찾음 | 예치 장부가 있는 컨트랙트에서 특권 함수가 임의 대상·임의 금액으로 저수준 `call`을 실행하면 별도로 탐지(`detect_arbitrary_call_drain`) |

## 독립 제작 40케이스 검증 (1차, GPT로 생성한 practice dataset)

저희가 만들지 않은, 별도로 GPT에게 생성을 요청한 30개 신규 샘플(`gpt_dataset/` — BENIGN 10 ·
MALICIOUS 10 · UNCERTAIN 10, 정답 라벨은 `datasets_legacy/gpt_30/manifest.json`)로 교차 검증했습니다.

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

**UNCERTAIN 처리 변경**: 이전 버전은 오류 상황 외에는 대부분 B/M으로 확정했지만,
현재는 위의 불확실성 규칙을 별도로 적용합니다. 데이터셋의 `U` 파일명을 판정에 사용하지 않습니다.
무제한 발행이나 소유자 전용 전송 예외처럼 기존 악성 기준에 해당하면 `MALICIOUS`를 유지하고,
외부 구현 확인이 필요한 경우에는 `UNCERTAIN`을 출력합니다.
기존 표의 B/M 결과는 유지되며, `variants/V6_ImmutableProxy.sol`은 외부 구현이 제공되지 않아
이제 `UNCERTAIN`입니다.

## 알려진 한계
- 정규식·괄호 매칭 기반 경량 파서이며 완전한 Solidity 문법 파서(예: `solc` AST)는
  아닙니다. 매우 복잡한 중첩 구조나 비표준적인 포맷팅에서는 함수/모디파이어 경계
  인식이 실패할 수 있습니다. 감지한 구문 오류는 `UNCERTAIN`으로 처리하지만,
  모든 Solidity 구문 오류나 분석 누락을 검출하지는 못합니다.
- 상속(`is`)으로 여러 컨트랙트에 로직이 분산된 경우, 부모 컨트랙트의 모디파이어나
  상태변수까지는 추적하지 않고 파일 내 각 컨트랙트를 독립적으로 봅니다. 악성 근거가 없으면 `UNCERTAIN`입니다.
- `import` 가 있는 멀티파일 컨트랙트는 가정하지 않습니다 (공개 샘플과 동일하게
  단일 파일 자기완결을 전제). import가 있으면 악성 근거가 없는 경우 `UNCERTAIN`입니다.
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
variants2/           # 가변 상한/증가량 불일치/승인 우회/재진입 검증용 변형 8종
variants3/           # 300케이스 확장 검증에서 발견한 버그 재현용 변형 3종
gpt_dataset/         # 별도로 GPT에게 생성 요청한 독립 검증용 30종 + 정답(manifest.json)
```

## UNCERTAIN 추가 보강 검증

기존에 확정 판정을 내렸던 U 그룹 51개를 검토했습니다. 아래 파일명은 검토 결과를
찾기 위한 참조일 뿐 분석기는 파일명이나 계약명의 B/M/U 문자열을 판정에 사용하지 않습니다.

| 구조 (대표 사례) | 개수 | 변경 후 | 근거 |
|---|---:|---|---|
| 송·수신자 양쪽 차단 정책 (U002) | 7 | UNCERTAIN | 정상 차단 정책과 선택적 동결 악용을 운영 정보 없이 구분하기 어려움 |
| 공개 ETH 수신 후 관리자 회수 (U003) | 7 | UNCERTAIN | 장부가 없어도 수신 자금이 관리자 소유라고 확정할 수 없음 |
| 관리자에 의한 예치금 출금 중단 (U012) | 6 | UNCERTAIN | 긴급 중단과 장기 동결을 정책·운영 정보 없이 구분하기 어려움 |
| 관리자 업그레이드 프록시 (U016) | 6 | UNCERTAIN | 외부 구현과 업그레이드 권한의 신뢰성을 확인할 수 없음 |
| 상한 없는 특권 발행 (U001) | 7 | MALICIOUS 유지 | 악성 그룹 M013의 특권 발행과 같은 위험; 영 주소 검사는 발행 상한이 아님 |
| 관리자만 전송 제한 우회 (U009) | 6 | MALICIOUS 유지 | 관리자 예외가 코드로 확인됨 |
| 특권 발행 및 타인 잔고 소각 (U010) | 6 | MALICIOUS 유지 | bridge라는 이름만으로 외부 담보 검증이나 소각 동의가 있다고 추정할 수 없음 |
| 상한 있는 설정만 존재 (U014) | 6 | BENIGN 유지 | 실제 수수료 적용·전송 경로가 없어 추가적인 불확실성 근거를 발견하지 못함 |

300개 결과: B 100개 모두 BENIGN, M 100개 모두 MALICIOUS,
U 100개는 UNCERTAIN 75 / MALICIOUS 19 / BENIGN 6입니다.
B/M/U를 정답 구분으로 간주하고 정답 +1, UNCERTAIN 출력 0, 오답 -1로 계산하면
`200 - 25 = 175점`입니다 (이전 149점). U가 미확정 샘플이라는 뜻이면 전체 실제 점수는
별도 정답 없이는 확정할 수 없습니다. 같은 데이터로 보강·검증했으므로 비공개 데이터 성능을 보장하지 않습니다.

양쪽 차단 정책에 관리자 예외가 추가되거나, 프록시 구현을 누구나 바꿀 수 있거나,
별도 자산 탈취 경로가 존재하면 MALICIOUS를 유지하는 회귀 테스트도 포함합니다.

## SJH 독립 데이터셋 평가

`SJH_dataset/trust404_solidity_300/cases`의 300개를 현재 분석기로 평가했습니다.
정답은 BENIGN 120 / MALICIOUS 120 / UNCERTAIN 60개이며, 판정에는 정답 파일을 사용하지 않습니다.

| 실제 정답 | BENIGN 판정 | MALICIOUS 판정 | UNCERTAIN 판정 |
|---|---:|---:|---:|
| BENIGN | 94 | 1 | 25 |
| MALICIOUS | 89 | 21 | 10 |
| UNCERTAIN | 0 | 7 | 53 |

정답 115, 오답 97, 판단 보류 88개로 **115 - 97 = 18점 / 최대 240점**입니다.
악성 89개를 BENIGN으로 놓치는 한계가 확인되었습니다. 앞의 자체 데이터셋 점수를
일반화 성능으로 해석해서는 안 됩니다.

재현 명령:

```bash
mkdir -p evaluation_results
bash run.sh SJH_dataset/trust404_solidity_300/cases > evaluation_results/sjh_predictions.json
python3 validate_schema.py evaluation_results/sjh_predictions.json SJH_dataset/trust404_solidity_300/cases
python3 SJH_dataset/trust404_solidity_300/evaluate.py evaluation_results/sjh_predictions.json > evaluation_results/sjh_score.json
```

상세 결과는 `evaluation_results/sjh_predictions.json`과 `evaluation_results/sjh_score.json`에 있습니다.

기존 저장소의 30개 샘플과 정답은 `datasets_legacy/gpt_30/`에 보존했습니다. 현재 `gpt_dataset/`은 300개 확장 데이터입니다.
