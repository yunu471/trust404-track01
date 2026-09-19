// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICallAuthority { function allowed(address caller, address target, uint256 value, bytes4 selector) external view returns (bool); }
contract Module2012 {
    ICallAuthority public rules;
    constructor(address initialAuthorityAddress) { rules = ICallAuthority(initialAuthorityAddress); }
    receive() external payable {}
    function perform(address target, uint256 value, bytes calldata payload) external returns (bytes memory) {
        bytes4 selector; assembly { selector := calldataload(payload.offset) }
        require(rules.allowed(msg.sender, target, value, selector), "denied"); (bool ok, bytes memory result) = target.call{value: value}(payload); require(ok, "call"); return result;
    }
}
