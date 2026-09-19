// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0207 {
    address public steward;
    bool public halted;
    mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; credits[msg.sender] = 1_000_000 ether; }
    function configure(bool value) external { require(msg.sender == steward, "denied"); halted = value; }
    function handle(address to, uint256 amount) external returns (bool) {
        require(!halted, "stopped");
        require(credits[msg.sender] >= amount, "funds");
        credits[msg.sender] -= amount; credits[to] += amount; return true;
    }
}
