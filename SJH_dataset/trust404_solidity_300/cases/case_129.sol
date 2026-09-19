// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0303 {
    address public governor;
    mapping(address => uint256) public accounts;
    constructor() { governor = msg.sender; }
    receive() external payable { accounts[msg.sender] += msg.value; }
    function perform(address target, bytes calldata payload) external {
        require(msg.sender == governor, "unauthorized");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
