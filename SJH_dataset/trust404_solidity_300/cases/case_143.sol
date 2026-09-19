// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2006 {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function processRequest(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        require(msg.sender == owner, "denied"); (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
