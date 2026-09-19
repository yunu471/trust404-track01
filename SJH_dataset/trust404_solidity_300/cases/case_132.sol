// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1002 {
    mapping(address => uint256) public credits;
    constructor() payable {}
    function credit(address account, uint256 units) external { credits[account] += units; }
    function updateRecord(uint256 units) external {
        require(credits[msg.sender] >= units, "units"); credits[msg.sender] -= units;
        uint256 payout = (units + 99) / 100;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
