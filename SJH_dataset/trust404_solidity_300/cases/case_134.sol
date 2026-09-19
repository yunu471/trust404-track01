// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0705 {
    address public a7;
    address public i6;
    function commitState(address initialImplementationAddress) external {
        require(a7 == address(0), "initialized");
        a7 = msg.sender; i6 = initialImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = i6.delegatecall(msg.data); require(ok, "failed"); }
}
