// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign021V0 {
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
        require(amount != 0, "empty");
        p.amount = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
