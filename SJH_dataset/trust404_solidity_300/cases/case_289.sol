// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISupplyRules { function maximum(address token) external view returns (uint256); }
contract Module0112 {
    address public steward;
    ISupplyRules public rules;
    uint256 public issued;
    mapping(address => uint256) public credits;
    constructor(address initialRulesAddress) { steward = msg.sender; rules = ISupplyRules(initialRulesAddress); }
    function reconcile(address receiver, uint256 amount) external {
        require(msg.sender == steward, "denied");
        require(issued + amount <= rules.maximum(address(this)), "limit");
        issued += amount;
        credits[receiver] += amount;
    }
}
