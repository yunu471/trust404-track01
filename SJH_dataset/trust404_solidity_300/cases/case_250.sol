// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1502 {
    mapping(address => uint256) public credits;
    function deposit() external payable { credits[msg.sender] += msg.value; }
    function updateRecord(bytes[] calldata calls) external payable {
        for (uint256 i; i < calls.length; i++) { (bool ok,) = address(this).delegatecall(calls[i]); require(ok, "call"); }
    }
    function withdraw() external { uint256 amount = credits[msg.sender]; credits[msg.sender] = 0; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
