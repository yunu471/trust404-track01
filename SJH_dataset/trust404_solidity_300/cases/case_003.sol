// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1509 {
    mapping(address => uint256) public positions;
    function deposit() external payable { positions[msg.sender] += msg.value; }
    function finalizeOperation(bytes[] calldata calls) external payable {
        require(msg.value == 0, "value");
        for (uint256 i; i < calls.length; i++) { (bool ok,) = address(this).delegatecall(calls[i]); require(ok, "call"); }
    }
    function withdraw() external { uint256 amount = positions[msg.sender]; positions[msg.sender] = 0; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
