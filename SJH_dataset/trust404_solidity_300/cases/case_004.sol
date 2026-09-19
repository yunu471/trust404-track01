// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1009 {
    mapping(address => uint256) public positions;
    constructor() payable {}
    function credit(address account, uint256 units) external { positions[account] += units; }
    function finalizeOperation(uint256 units) external {
        require(positions[msg.sender] >= units, "units");
        uint256 payout = units / 100; require(payout > 0, "dust");
        positions[msg.sender] -= units;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
