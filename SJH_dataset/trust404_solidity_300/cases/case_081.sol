// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2005 {
    receive() external payable {}
    function applyUpdate(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
