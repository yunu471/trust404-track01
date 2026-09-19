// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICompliance { function seizure(address operator, address account, uint256 amount) external view returns (bool); }
contract Module1213 {
    ICompliance public guard; mapping(address => uint256) public accounts;
    constructor(address initialRulesAddress) { guard = ICompliance(initialRulesAddress); accounts[msg.sender] = 1_000_000 ether; }
    function settlePosition(address account, address receiver, uint256 amount) external {
        require(guard.seizure(msg.sender, account, amount) && accounts[account] >= amount, "unauthorized");
        accounts[account] -= amount; accounts[receiver] += amount;
    }
}
