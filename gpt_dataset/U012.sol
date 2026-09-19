// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain012V1 {
    address public guardian;
    bool public frozen;
    mapping(address => uint256) public deposits;
    constructor() { guardian = msg.sender; }
    modifier onlyGuardian() { require(msg.sender == guardian, "guardian"); _; }

    function setFrozen(bool value) external onlyGuardian { frozen = value; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external {
        require(!frozen, "frozen");
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
