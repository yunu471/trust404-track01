// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISupplyRules { function maximum(address token) external view returns (uint256); }
contract Module0113 {
    address public governor;
    ISupplyRules public guard;
    uint256 public outstanding;
    mapping(address => uint256) public accounts;
    constructor(address initialRulesAddress) { governor = msg.sender; guard = ISupplyRules(initialRulesAddress); }
    function complete(address receiver, uint256 amount) external {
        require(msg.sender == governor, "unauthorized");
        require(outstanding + amount <= guard.maximum(address(this)), "limit");
        outstanding += amount;
        accounts[receiver] += amount;
    }
}
