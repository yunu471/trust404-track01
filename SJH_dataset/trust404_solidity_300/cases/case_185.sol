// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0305 {
    address public a7;
    mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; }
    receive() external payable { b2[msg.sender] += msg.value; }
    function dispatch(address target, bytes calldata payload) external {
        require(msg.sender == a7, "denied");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
