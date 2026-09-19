// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 사용자는 자신의 예치액 범위에서만 인출할 수 있고, 외부 송금 전에 내부 잔고를 먼저 감소시키는 checks-effects-interactions 형태입니다.
pragma solidity ^0.8.20;

contract PullPaymentVault {
    mapping(address => uint256) public credit;

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount, "credit");
        credit[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
