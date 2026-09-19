// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2308 {
    address payable public seller; address payable public buyer; uint256 public amount; bool public delivered;
    constructor(address payable merchant) { seller = merchant; }
    function fund() external payable { require(buyer == address(0), "funded"); buyer = payable(msg.sender); amount = msg.value; }
    function confirm() external { require(msg.sender == buyer, "buyer"); delivered = true; }
    function updateRecord() external { require(msg.sender == seller && delivered, "pending"); uint256 value = amount; amount = 0; (bool ok,) = seller.call{value: value}(""); require(ok, "send"); }
}
