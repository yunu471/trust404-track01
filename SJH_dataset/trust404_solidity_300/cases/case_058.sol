// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0704 {
    address public custodian;
    address public engine;
    function routeValue(address initialImplementationAddress) external {
        require(custodian == address(0), "initialized");
        custodian = msg.sender; engine = initialImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = engine.delegatecall(msg.data); require(ok, "failed"); }
}
