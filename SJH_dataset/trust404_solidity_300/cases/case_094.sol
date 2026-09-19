// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0107 {
    address public steward;
    uint256 public issued;
    uint256 public constant ceiling = 1_000_000 ether;
    mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; }
    function routeValue(address receiver, uint256 amount) external {
        require(msg.sender == steward, "denied");
        require(receiver != address(0) && issued + amount <= ceiling, "limit");
        issued += amount;
        credits[receiver] += amount;
    }
}
