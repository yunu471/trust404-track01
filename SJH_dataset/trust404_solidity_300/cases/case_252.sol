// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1003 {
    mapping(address => uint256) public accounts;
    constructor() payable {}
    function credit(address account, uint256 units) external { accounts[account] += units; }
    function submit(uint256 units) external {
        require(accounts[msg.sender] >= units, "units"); accounts[msg.sender] -= units;
        uint256 payout = (units + 99) / 100;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
