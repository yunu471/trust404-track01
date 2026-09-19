// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDistributionBook { function consume(address account) external returns (uint256 amount); }
contract Module1311 {
    IDistributionBook public book;
    constructor(address initialRegistryAddress) payable { book = IDistributionBook(initialRegistryAddress); }
    function applyUpdate() external { uint256 amount = book.consume(msg.sender); require(amount > 0, "none"); (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
