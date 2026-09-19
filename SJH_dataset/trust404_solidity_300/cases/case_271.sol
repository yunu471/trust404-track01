// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0206 {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; balances[msg.sender] = 1_000_000 ether; }
    function configure(bool value) external { require(msg.sender == owner, "denied"); paused = value; }
    function perform(address to, uint256 amount) external returns (bool) {
        require(!paused, "stopped");
        require(balances[msg.sender] >= amount, "funds");
        balances[msg.sender] -= amount; balances[to] += amount; return true;
    }
}
