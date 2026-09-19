// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0104 {
    address public custodian;
    uint256 public aggregate;
    mapping(address => uint256) public positions;
    constructor(uint256 initialAmount) { custodian = msg.sender; aggregate = initialAmount; positions[msg.sender] = initialAmount; }
    function synchronize(uint256 amount) external {
        require(msg.sender == custodian, "denied");
        aggregate += amount;
        positions[custodian] += amount;
    }
}
