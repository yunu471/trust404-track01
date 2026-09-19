// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0208 {
    address public governor;
    bool public stopped;
    mapping(address => uint256) public accounts;
    constructor() { governor = msg.sender; accounts[msg.sender] = 1_000_000 ether; }
    function configure(bool value) external { require(msg.sender == governor, "unauthorized"); stopped = value; }
    function dispatch(address to, uint256 amount) external returns (bool) {
        require(!stopped, "stopped");
        require(accounts[msg.sender] >= amount, "insufficient");
        accounts[msg.sender] -= amount; accounts[to] += amount; return true;
    }
}
