// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1501 {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function complete(bytes[] calldata calls) external payable {
        for (uint256 i; i < calls.length; i++) { (bool ok,) = address(this).delegatecall(calls[i]); require(ok, "call"); }
    }
    function withdraw() external { uint256 amount = balances[msg.sender]; balances[msg.sender] = 0; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
