// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious063V2 {
    address public owner;
    mapping(address => uint256) public unlockAt;
    mapping(address => uint256) public deposits;

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        if (unlockAt[msg.sender] == 0) unlockAt[msg.sender] = block.timestamp + 1 days;
    }

    function delay(address user, uint256 secondsMore) external onlyOwner {
        unlockAt[user] += secondsMore;
    }

    function withdraw() external {
        if (msg.sender != owner) require(block.timestamp >= unlockAt[msg.sender], "locked");
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
