// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0701 {
    address public owner;
    address public implementation;
    function synchronize(address initialImplementationAddress) external {
        require(owner == address(0), "initialized");
        owner = msg.sender; implementation = initialImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = implementation.delegatecall(msg.data); require(ok, "failed"); }
}
