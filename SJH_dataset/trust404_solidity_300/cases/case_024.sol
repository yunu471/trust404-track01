// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IModuleAdmin { function approved(address target, bytes4 selector) external view returns (bool); }
contract Module0312 {
    IModuleAdmin public controller;
    constructor(address initialAuthorityAddress) { controller = IModuleAdmin(initialAuthorityAddress); }
    function processRequest(address target, bytes calldata payload) external {
        bytes4 selector; assembly { selector := calldataload(payload.offset) }
        require(controller.approved(target, selector), "denied");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
