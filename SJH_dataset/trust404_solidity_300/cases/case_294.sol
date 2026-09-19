// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2303 {
    address payable public seller; address public buyer; uint256 public amount;
    constructor(address payable merchant) { seller = merchant; }
    function fund() external payable { require(buyer == address(0), "funded"); buyer = msg.sender; amount = msg.value; }
    function perform() external { require(msg.sender == seller, "seller"); uint256 value = amount; amount = 0; (bool ok,) = seller.call{value: value}(""); require(ok, "send"); }
}
