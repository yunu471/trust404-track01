// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2406 {
    address public owner;
    constructor() { owner = msg.sender; }
    function submit() external { require(msg.sender == owner, "denied"); (bool ok,) = payable(owner).call{value: address(this).balance}(""); require(ok, "send"); }
}
