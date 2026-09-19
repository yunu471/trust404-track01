// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain054V3 {
    address public admin;
    uint256 public unlockAt;
    mapping(address => uint256) public deposits;
    constructor(uint256 t) {
        admin = msg.sender;
        unlockAt = t;
    }
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }

    function setUnlock(uint256 t) external onlyAdmin { unlockAt = t; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= unlockAt, "locked");
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
