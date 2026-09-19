// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain034V3 {
    address public compliance;
    mapping(address => bool) public blocked;
    mapping(address => uint256) public balanceOf;
    constructor(uint256 supply) {
        compliance = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyCompliance() { require(msg.sender == compliance, "compliance"); _; }

    function setBlocked(address user, bool value) external onlyCompliance { blocked[user] = value; }

    function transfer(address to, uint256 amount) external {
        require(!blocked[msg.sender] && !blocked[to], "blocked");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
