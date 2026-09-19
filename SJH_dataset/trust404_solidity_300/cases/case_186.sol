// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1010 {
    mapping(address => uint256) public b2;
    constructor() payable {}
    function credit(address account, uint256 units) external { b2[account] += units; }
    function routeValue(uint256 units) external {
        require(b2[msg.sender] >= units, "units");
        uint256 payout = units / 100; require(payout > 0, "dust");
        b2[msg.sender] -= units;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
