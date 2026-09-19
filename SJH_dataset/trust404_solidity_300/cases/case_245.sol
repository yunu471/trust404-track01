// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0108 {
    address public governor;
    uint256 public outstanding;
    uint256 public constant maximum = 1_000_000 ether;
    mapping(address => uint256) public accounts;
    constructor() { governor = msg.sender; }
    function commitState(address receiver, uint256 amount) external {
        require(msg.sender == governor, "unauthorized");
        require(receiver != address(0) && outstanding + amount <= maximum, "limit");
        outstanding += amount;
        accounts[receiver] += amount;
    }
}
