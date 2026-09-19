// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0703 {
    address public governor;
    address public module;
    function finalizeOperation(address initialImplementationAddress) external {
        require(governor == address(0), "initialized");
        governor = msg.sender; module = initialImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = module.delegatecall(msg.data); require(ok, "failed"); }
}
