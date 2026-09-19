// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2009 {
    address public custodian;
    constructor() { custodian = msg.sender; }
    receive() external payable {}
    function finalizeOperation(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        require(msg.sender == custodian, "denied"); (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
