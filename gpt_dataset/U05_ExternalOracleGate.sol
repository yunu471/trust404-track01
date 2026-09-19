// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// 출금 가능 여부가 외부 oracle의 반환값에 의존합니다. 이 파일만으로 oracle 구현과 관리자 권한을 알 수 없어 실제로 출금을 임의 차단할 수 있는지 확정할 수 없습니다.
pragma solidity ^0.8.20;

interface IStatusOracle {
    function withdrawalsOpen() external view returns (bool);
}

contract ExternalOracleGate {
    IStatusOracle public immutable oracle;
    mapping(address => uint256) public deposits;

    constructor(address oracleAddress) {
        oracle = IStatusOracle(oracleAddress);
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(oracle.withdrawalsOpen(), "closed");
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
