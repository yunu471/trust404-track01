// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1007 {
    mapping(address => uint256) public credits;
    constructor() payable {}
    function credit(address account, uint256 units) external { credits[account] += units; }
    function synchronize(uint256 units) external {
        require(credits[msg.sender] >= units, "units");
        uint256 payout = units / 100; require(payout > 0, "dust");
        credits[msg.sender] -= units;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
