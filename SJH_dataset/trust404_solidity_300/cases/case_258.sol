// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILiabilityBook { function liabilities(address vault) external view returns (uint256); }
contract Module1611 {
    address public owner; ILiabilityBook public book;
    constructor(address initialAccountingAddress) { owner = msg.sender; book = ILiabilityBook(initialAccountingAddress); }
    receive() external payable {}
    function dispatch() external { require(msg.sender == owner, "denied"); uint256 excess = address(this).balance - book.liabilities(address(this)); (bool ok,) = payable(owner).call{value: excess}(""); require(ok, "send"); }
}
