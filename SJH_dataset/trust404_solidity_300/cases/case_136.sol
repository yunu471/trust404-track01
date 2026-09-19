// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2409 {
    address public custodian;
    constructor() { custodian = msg.sender; }
    function processRequest() external { require(msg.sender == custodian, "denied"); (bool ok,) = payable(custodian).call{value: address(this).balance}(""); require(ok, "send"); }
}
