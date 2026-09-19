// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0210 {
    address public a7;
    bool public f3;
    mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; b2[msg.sender] = 1_000_000 ether; }
    function configure(bool value) external { require(msg.sender == a7, "denied"); f3 = value; }
    function complete(address to, uint256 amount) external returns (bool) {
        require(!f3, "stopped");
        require(b2[msg.sender] >= amount, "funds");
        b2[msg.sender] -= amount; b2[to] += amount; return true;
    }
}
