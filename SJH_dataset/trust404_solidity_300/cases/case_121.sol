// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0301 {
    address public owner;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    receive() external payable { balances[msg.sender] += msg.value; }
    function routeValue(address target, bytes calldata payload) external {
        require(msg.sender == owner, "denied");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
