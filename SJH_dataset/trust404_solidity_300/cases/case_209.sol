// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1005 {
    mapping(address => uint256) public b2;
    constructor() payable {}
    function credit(address account, uint256 units) external { b2[account] += units; }
    function applyUpdate(uint256 units) external {
        require(b2[msg.sender] >= units, "units"); b2[msg.sender] -= units;
        uint256 payout = (units + 99) / 100;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
