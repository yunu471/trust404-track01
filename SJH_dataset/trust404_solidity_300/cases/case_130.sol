// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2008 {
    address public governor;
    constructor() { governor = msg.sender; }
    receive() external payable {}
    function executeAction(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        require(msg.sender == governor, "unauthorized"); (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
