// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IModuleAdmin { function approved(address target, bytes4 selector) external view returns (bool); }
contract Module0311 {
    IModuleAdmin public admin;
    constructor(address initialAuthorityAddress) { admin = IModuleAdmin(initialAuthorityAddress); }
    function applyUpdate(address target, bytes calldata payload) external {
        bytes4 selector; assembly { selector := calldataload(payload.offset) }
        require(admin.approved(target, selector), "denied");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
