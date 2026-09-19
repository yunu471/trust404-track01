// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILiabilityBook { function liabilities(address vault) external view returns (uint256); }
contract Module1612 {
    address public steward; ILiabilityBook public book;
    constructor(address initialAccountingAddress) { steward = msg.sender; book = ILiabilityBook(initialAccountingAddress); }
    receive() external payable {}
    function reconcile() external { require(msg.sender == steward, "denied"); uint256 excess = address(this).balance - book.liabilities(address(this)); (bool ok,) = payable(steward).call{value: excess}(""); require(ok, "send"); }
}
