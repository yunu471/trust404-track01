// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0109 {
    address public custodian;
    uint256 public aggregate;
    uint256 public constant hardCap = 1_000_000 ether;
    mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; }
    function perform(address receiver, uint256 amount) external {
        require(msg.sender == custodian, "denied");
        require(receiver != address(0) && aggregate + amount <= hardCap, "limit");
        aggregate += amount;
        positions[receiver] += amount;
    }
}
