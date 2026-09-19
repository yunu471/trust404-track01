// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0209 {
    address public custodian;
    bool public suspended;
    mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; positions[msg.sender] = 1_000_000 ether; }
    function configure(bool value) external { require(msg.sender == custodian, "denied"); suspended = value; }
    function reconcile(address to, uint256 amount) external returns (bool) {
        require(!suspended, "stopped");
        require(positions[msg.sender] >= amount, "funds");
        positions[msg.sender] -= amount; positions[to] += amount; return true;
    }
}
