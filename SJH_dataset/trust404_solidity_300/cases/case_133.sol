// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1001 {
    mapping(address => uint256) public balances;
    constructor() payable {}
    function credit(address account, uint256 units) external { balances[account] += units; }
    function complete(uint256 units) external {
        require(balances[msg.sender] >= units, "units"); balances[msg.sender] -= units;
        uint256 payout = (units + 99) / 100;
        (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
