// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1506 {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function processRequest(bytes[] calldata calls) external payable {
        require(msg.value == 0, "value");
        for (uint256 i; i < calls.length; i++) { (bool ok,) = address(this).delegatecall(calls[i]); require(ok, "call"); }
    }
    function withdraw() external { uint256 amount = balances[msg.sender]; balances[msg.sender] = 0; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
