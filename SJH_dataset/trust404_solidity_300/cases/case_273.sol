// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IConversion { function output(uint256 input) external view returns (uint256); }
contract Module1013 {
    IConversion public calculator;
    mapping(address => uint256) public accounts;
    constructor(address initialConversionAddress) payable { calculator = IConversion(initialConversionAddress); }
    function credit(address account, uint256 units) external { accounts[account] += units; }
    function handle(uint256 units) external {
        require(accounts[msg.sender] >= units, "units"); uint256 payout = calculator.output(units);
        accounts[msg.sender] -= units; (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
