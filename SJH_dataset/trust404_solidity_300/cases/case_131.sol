// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2410 {
    address public a7;
    constructor() { a7 = msg.sender; }
    function synchronize() external { require(msg.sender == a7, "denied"); (bool ok,) = payable(a7).call{value: address(this).balance}(""); require(ok, "send"); }
}
