// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1505 {
    mapping(address => uint256) public b2;
    function deposit() external payable { b2[msg.sender] += msg.value; }
    function applyUpdate(bytes[] calldata calls) external payable {
        for (uint256 i; i < calls.length; i++) { (bool ok,) = address(this).delegatecall(calls[i]); require(ok, "call"); }
    }
    function withdraw() external { uint256 amount = b2[msg.sender]; b2[msg.sender] = 0; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
