// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICallAuthority { function allowed(address caller, address target, uint256 value, bytes4 selector) external view returns (bool); }
contract Module2011 {
    ICallAuthority public policy;
    constructor(address initialAuthorityAddress) { policy = ICallAuthority(initialAuthorityAddress); }
    receive() external payable {}
    function commitState(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        bytes4 selector; assembly { selector := calldataload(payload.offset) }
        require(policy.allowed(msg.sender, target, value, selector), "denied"); (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
