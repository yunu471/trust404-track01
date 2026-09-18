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

| **비대칭 전송 제한 (Honeypot)** | `transfer`/`transferFrom` 류 함수에서 전송 가능 여부를 결정하는 조건을 찾습니다. 그 조건이 **모든 주소에 동일하게 적용되는 전역 플래그**(예: `paused`)면 대칭 제약으로 `BENIGN`(가용성 제약일 뿐 자산 이전 경로가 아님). 반면 조건이 **`msg.sender` 별로 값이 다른 매핑**이고 그 매핑을 소유자만 바꿀 수 있거나, 전역 플래그라도 `msg.sender == owner` 류로 소유자만 예외 처리되어 있으면 비대칭 구조로 `MALICIOUS` 입니다. |

| **Delegatecall 백도어** | `delegatecall` 호출 대상이 생성자에서 한 번만 고정된 `immutable` 주소(세터 없음, 함수 파라미터도 아님)면 프록시 패턴으로 보고 `BENIGN`(낮은 위험으로 부기). 그 외 — 함수 파라미터로 받은 주소, 세터가 있는 가변 상태변수 등 — 는 스토리지 문맥을 공유하는 임의 코드 실행 경로이므로 `MALICIOUS` 입니다. |

| **예치금 우회 인출 (Fund drain)** | `deposit`류 payable 함수가 사용자별 매핑(`deposits`, `stake` 등)에 잔고를 기록하는 컨트랙트에서, 별도 함수가 그 매핑 회계를 거치지 않고 `address(this).balance` 전체를 이동시키거나 `selfdestruct` 하면 사용자 예치금 탈취 경로로 보아 `MALICIOUS`. 그런 예치 매핑이 애초에 없는 컨트랙트에서 소유자가 잔고를 회수하는 것은 강제 송금된 ETH 회수로 보아 `BENIGN` 입니다 (README의 자산 귀속 가정 3번). |

네 규칙 모두에서 발견되지 않으면 `BENIGN` 이며, 컨트랙트 정의 자체를 인식하지
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
비예치 컨트랙트의 잔고 회수 / 불변 프록시 delegatecall)을 두어 하드코딩이 아닌
로직 기반 판별이 P1~P5 이외의 패턴에도 일반화되는지 확인했습니다.

## 알려진 한계
- 정규식·괄호 매칭 기반 경량 파서이며 완전한 Solidity 문법 파서(예: `solc` AST)는
  아닙니다. 매우 복잡한 중첩 구조나 비표준적인 포맷팅에서는 함수/모디파이어 경계
  인식이 실패할 수 있으며, 그 경우 해당 파일은 안전하게 `UNCERTAIN` 으로
  떨어집니다 (오답 감점보다 무득점을 택함).
- 상속(`is`)으로 여러 컨트랙트에 로직이 분산된 경우, 부모 컨트랙트의 모디파이어나
  상태변수까지는 추적하지 않고 파일 내 각 컨트랙트를 독립적으로 봅니다.
- `import` 가 있는 멀티파일 컨트랙트는 가정하지 않습니다 (공개 샘플과 동일하게
  단일 파일 자기완결을 전제).

## 파일 구성
```
run.sh              # 비대화형 진입점
analyzer.py         # 파서 + 탐지 규칙 + CLI 본체 (표준 라이브러리만 사용)
validate_schema.py  # 제출 전 자가 스키마 검증 (선택, 채점 파이프라인 외부)
schema.json          # 출제측 제공 스키마 원본 (검증용으로 동봉)
challenge_public/    # 공개 샘플 5종 (캘리브레이션 확인용, 채점에는 비공개셋 사용)
variants/            # 자체 제작 추가 검증용 변형 6종
```
