// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1004 {
    mapping(address => uint256) public positions;
    constructor() payable {}
    function credit(address account, uint256 units) external { positions[account] += units; }
    function settlePosition(uint256 units) external {
        require(positions[msg.sender] >= units, "units"); positions[msg.sender] -= units;
        uint256 payout = (units + 99) / 100;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
