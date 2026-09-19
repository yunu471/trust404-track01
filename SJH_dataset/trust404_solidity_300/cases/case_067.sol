// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0304 {
    address public custodian;
    mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; }
    receive() external payable { positions[msg.sender] += msg.value; }
    function handle(address target, bytes calldata payload) external {
        require(msg.sender == custodian, "denied");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
