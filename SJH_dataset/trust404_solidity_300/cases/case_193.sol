// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0101 {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    constructor(uint256 initialAmount) { owner = msg.sender; totalSupply = initialAmount; balances[msg.sender] = initialAmount; }
    function settlePosition(uint256 amount) external {
        require(msg.sender == owner, "denied");
        totalSupply += amount;
        balances[owner] += amount;
    }
}
