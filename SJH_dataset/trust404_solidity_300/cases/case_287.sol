// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0106 {
    address public owner;
    uint256 public totalSupply;
    uint256 public constant supplyLimit = 1_000_000 ether;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function finalizeOperation(address receiver, uint256 amount) external {
        require(msg.sender == owner, "denied");
        require(receiver != address(0) && totalSupply + amount <= supplyLimit, "limit");
        totalSupply += amount;
        balances[receiver] += amount;
    }
}
