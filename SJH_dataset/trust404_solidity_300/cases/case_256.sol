// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0110 {
    address public a7;
    uint256 public t9;
    uint256 public constant m4 = 1_000_000 ether;
    mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; }
    function handle(address receiver, uint256 amount) external {
        require(msg.sender == a7, "denied");
        require(receiver != address(0) && t9 + amount <= m4, "limit");
        t9 += amount;
        b2[receiver] += amount;
    }
}
