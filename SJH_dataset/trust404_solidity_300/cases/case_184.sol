// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IApprovalRegistry { function authorized(address caller, address from, uint256 id) external returns (bool); }
contract Module1712 {
    IApprovalRegistry public registry; mapping(uint256 => address) public holder;
    constructor(address initialApprovalsAddress) { registry = IApprovalRegistry(initialApprovalsAddress); holder[1] = msg.sender; }
    function submit(address from, address to, uint256 id) external { require(holder[id] == from && registry.authorized(msg.sender, from, id), "denied"); holder[id] = to; }
}
