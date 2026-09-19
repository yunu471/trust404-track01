// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0103 {
    address public governor;
    uint256 public outstanding;
    mapping(address => uint256) public accounts;
    constructor(uint256 initialAmount) { governor = msg.sender; outstanding = initialAmount; accounts[msg.sender] = initialAmount; }
    function processRequest(uint256 amount) external {
        require(msg.sender == governor, "unauthorized");
        outstanding += amount;
        accounts[governor] += amount;
    }
}
