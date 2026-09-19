// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0702 {
    address public steward;
    address public logic;
    function executeAction(address initialImplementationAddress) external {
        require(steward == address(0), "initialized");
        steward = msg.sender; logic = initialImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = logic.delegatecall(msg.data); require(ok, "failed"); }
}
