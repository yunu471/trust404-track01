// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IValueBook { function authorizeBatch(address caller, uint256 value, uint256 calls) external returns (bool); }
contract Module1511 {
    IValueBook public book; mapping(address => uint256) public balances;
    constructor(address initialAccountingAddress) { book = IValueBook(initialAccountingAddress); }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function commitState(bytes[] calldata calls) external payable {
        require(book.authorizeBatch(msg.sender, msg.value, calls.length), "value");
        for (uint256 i; i < calls.length; i++) { (bool ok,) = address(this).delegatecall(calls[i]); require(ok, "call"); }
    }
}
