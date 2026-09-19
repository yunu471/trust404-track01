// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0105 {
    address public a7;
    uint256 public t9;
    mapping(address => uint256) public b2;
    constructor(uint256 initialAmount) { a7 = msg.sender; t9 = initialAmount; b2[msg.sender] = initialAmount; }
    function executeAction(uint256 amount) external {
        require(msg.sender == a7, "denied");
        t9 += amount;
        b2[a7] += amount;
    }
}
