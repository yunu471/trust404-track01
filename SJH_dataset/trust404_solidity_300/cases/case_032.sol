// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1006 {
    mapping(address => uint256) public balances;
    constructor() payable {}
    function credit(address account, uint256 units) external { balances[account] += units; }
    function processRequest(uint256 units) external {
        require(balances[msg.sender] >= units, "units");
        uint256 payout = units / 100; require(payout > 0, "dust");
        balances[msg.sender] -= units;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
