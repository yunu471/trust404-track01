// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IModuleAdmin { function approved(address target, bytes4 selector) external view returns (bool); }
contract Module0313 {
    IModuleAdmin public authority;
    constructor(address initialAuthorityAddress) { authority = IModuleAdmin(initialAuthorityAddress); }
    function synchronize(address target, bytes calldata payload) external {
        bytes4 selector; assembly { selector := calldataload(payload.offset) }
        require(authority.approved(target, selector), "unauthorized");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
