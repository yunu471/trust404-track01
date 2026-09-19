// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious037V1 {
    address public owner;
    mapping(address => uint256) public deposits;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function executeModule(address target, bytes calldata data) external onlyOwner {
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegate");
    }
}
