// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 각 사용자의 예치금은 사용자가 지정한 잠금 시간 이후 본인만 인출할 수 있습니다. 관리자가 잠금 시간을 연장하거나 자금을 가져가는 함수가 없습니다.
pragma solidity ^0.8.20;

contract TimeLockedDeposit {
    struct Position { uint256 amount; uint256 unlockAt; }
    mapping(address => Position) public positions;

    function deposit(uint256 lockSeconds) external payable {
        require(msg.value > 0, "value");
        Position storage p = positions[msg.sender];
        p.amount += msg.value;
        uint256 candidate = block.timestamp + lockSeconds;
        if (candidate > p.unlockAt) p.unlockAt = candidate;
    }

    function withdraw() external {
        Position storage p = positions[msg.sender];
        require(block.timestamp >= p.unlockAt, "locked");
        uint256 amount = p.amount;
        require(amount > 0, "empty");
        p.amount = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
