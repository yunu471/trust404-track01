// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 구매자가 입금하고 구매자만 release 또는 refund를 선택할 수 있으며, 임의의 제3자가 예치금을 탈취할 수 있는 관리자 출금 경로가 없습니다.
pragma solidity ^0.8.20;

contract TwoPartyEscrow {
    address public buyer;
    address payable public seller;
    uint256 public amount;
    bool public funded;
    bool public closed;

    constructor(address payable _seller) {
        buyer = msg.sender;
        seller = _seller;
    }

    function fund() external payable {
        require(msg.sender == buyer && !funded, "fund");
        funded = true;
        amount = msg.value;
    }

    function release() external {
        require(msg.sender == buyer && funded && !closed, "release");
        closed = true;
        (bool ok,) = seller.call{value: amount}("");
        require(ok, "send");
    }

    function refund() external {
        require(msg.sender == buyer && funded && !closed, "refund");
        closed = true;
        (bool ok,) = payable(buyer).call{value: amount}("");
        require(ok, "send");
    }
}
