// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2407 {
    address public steward;
    constructor() { steward = msg.sender; }
    function settlePosition() external { require(msg.sender == steward, "denied"); (bool ok,) = payable(steward).call{value: address(this).balance}(""); require(ok, "send"); }
}
