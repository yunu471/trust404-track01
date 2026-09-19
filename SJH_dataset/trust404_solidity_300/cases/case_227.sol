// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2007 {
    address public steward;
    constructor() { steward = msg.sender; }
    receive() external payable {}
    function synchronize(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        require(msg.sender == steward, "denied"); (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
