# Solidity Detection Dataset

새로 만든 샘플 30개 + 사용자가 제공한 원본 예제 5개를 포함합니다.

## 새 샘플 구성
- BENIGN: 10
- MALICIOUS: 10
- UNCERTAIN: 10

## 의도
단순 키워드 탐지보다 아래 의미를 구분하도록 구성했습니다.

- `owner`, `pause`, `mint`, `delegatecall`, `call`이 존재한다고 자동으로 악성으로 판정하지 않기
- 관리자 권한이 실제로 사용자 자산을 탈취/동결/희석하는지 보기
- 동일한 기능도 사용 목적이나 외부 구현체가 없으면 `UNCERTAIN`이 될 수 있음을 반영
- 함수 이름을 신뢰하지 않고 실제 상태 변경과 접근제어를 보기

`manifest.json`에 정답 라벨, 설명, 근거 함수가 들어 있습니다.
