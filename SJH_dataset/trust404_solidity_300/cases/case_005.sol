// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0102 {
    address public steward;
    uint256 public issued;
    mapping(address => uint256) public credits;
    constructor(uint256 initialAmount) { steward = msg.sender; issued = initialAmount; credits[msg.sender] = initialAmount; }
    function applyUpdate(uint256 amount) external {
        require(msg.sender == steward, "denied");
        issued += amount;
        credits[steward] += amount;
    }
}
