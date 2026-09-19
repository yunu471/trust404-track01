// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISupplyRules { function maximum(address token) external view returns (uint256); }
contract Module0111 {
    address public owner;
    ISupplyRules public policy;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    constructor(address initialRulesAddress) { owner = msg.sender; policy = ISupplyRules(initialRulesAddress); }
    function dispatch(address receiver, uint256 amount) external {
        require(msg.sender == owner, "denied");
        require(totalSupply + amount <= policy.maximum(address(this)), "limit");
        totalSupply += amount;
        balances[receiver] += amount;
    }
}
