// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2408 {
    address public governor;
    constructor() { governor = msg.sender; }
    function applyUpdate() external { require(msg.sender == governor, "unauthorized"); (bool ok,) = payable(governor).call{value: address(this).balance}(""); require(ok, "send"); }
}
