// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransferRules { function allowed(address from, address to, uint256 amount) external view returns (bool); }
contract Module0213 {
    ITransferRules public guard;
    mapping(address => uint256) public accounts;
    constructor(address initialRulesAddress) { guard = ITransferRules(initialRulesAddress); accounts[msg.sender] = 1_000_000 ether; }
    function settlePosition(address to, uint256 amount) external returns (bool) {
        require(guard.allowed(msg.sender, to, amount), "restricted");
        require(accounts[msg.sender] >= amount, "insufficient");
        accounts[msg.sender] -= amount; accounts[to] += amount; return true;
    }
}
