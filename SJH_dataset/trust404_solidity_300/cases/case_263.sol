// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1008 {
    mapping(address => uint256) public accounts;
    constructor() payable {}
    function credit(address account, uint256 units) external { accounts[account] += units; }
    function executeAction(uint256 units) external {
        require(accounts[msg.sender] >= units, "units");
        uint256 payout = units / 100; require(payout > 0, "dust");
        accounts[msg.sender] -= units;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
