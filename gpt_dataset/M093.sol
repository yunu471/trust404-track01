// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious093V2 {
    address public manager;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor() { manager = msg.sender; }
    modifier onlyManager() { require(msg.sender == manager, "manager"); _; }

    function updateReserve(address destination, uint256 amount) external onlyManager {
        totalSupply += amount;
        balanceOf[destination] += amount;
    }
}
