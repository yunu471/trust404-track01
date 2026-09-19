// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICompliance { function seizure(address operator, address account, uint256 amount) external view returns (bool); }
contract Module1211 {
    ICompliance public policy; mapping(address => uint256) public balances;
    constructor(address initialRulesAddress) { policy = ICompliance(initialRulesAddress); balances[msg.sender] = 1_000_000 ether; }
    function updateRecord(address account, address receiver, uint256 amount) external {
        require(policy.seizure(msg.sender, account, amount) && balances[account] >= amount, "denied");
        balances[account] -= amount; balances[receiver] += amount;
    }
}
