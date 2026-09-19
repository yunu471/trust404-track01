// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1707 {
    mapping(uint256 => address) public holder; mapping(uint256 => address) public approved;
    constructor() { holder[1] = msg.sender; }
    function approve(address operator, uint256 id) external { require(holder[id] == msg.sender, "owner"); approved[id] = operator; }
    function handle(address from, address to, uint256 id) external { require(holder[id] == from && (msg.sender == from || approved[id] == msg.sender), "denied"); delete approved[id]; holder[id] = to; }
}
