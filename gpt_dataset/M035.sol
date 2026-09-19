// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious035V4 {
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;
    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setFee(uint256 next) external onlyOwner {
        require(next <= 10000, "range");
        feeBps = next;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        uint256 fee = amount * feeBps / 10000;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - fee;
        balanceOf[owner] += fee;
    }
}
