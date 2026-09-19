// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICompliance { function seizure(address operator, address account, uint256 amount) external view returns (bool); }
contract Module1212 {
    ICompliance public rules; mapping(address => uint256) public credits;
    constructor(address initialRulesAddress) { rules = ICompliance(initialRulesAddress); credits[msg.sender] = 1_000_000 ether; }
    function submit(address account, address receiver, uint256 amount) external {
        require(rules.seizure(msg.sender, account, amount) && credits[account] >= amount, "denied");
        credits[account] -= amount; credits[receiver] += amount;
    }
}
