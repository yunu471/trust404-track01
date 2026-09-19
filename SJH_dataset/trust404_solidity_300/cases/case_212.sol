// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransferRules { function allowed(address from, address to, uint256 amount) external view returns (bool); }
contract Module0211 {
    ITransferRules public policy;
    mapping(address => uint256) public balances;
    constructor(address initialRulesAddress) { policy = ITransferRules(initialRulesAddress); balances[msg.sender] = 1_000_000 ether; }
    function updateRecord(address to, uint256 amount) external returns (bool) {
        require(policy.allowed(msg.sender, to, amount), "restricted");
        require(balances[msg.sender] >= amount, "funds");
        balances[msg.sender] -= amount; balances[to] += amount; return true;
    }
}
