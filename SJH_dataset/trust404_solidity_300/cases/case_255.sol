// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IConversion { function output(uint256 input) external view returns (uint256); }
contract Module1011 {
    IConversion public calculator;
    mapping(address => uint256) public balances;
    constructor(address initialConversionAddress) payable { calculator = IConversion(initialConversionAddress); }
    function credit(address account, uint256 units) external { balances[account] += units; }
    function commitState(uint256 units) external {
        require(balances[msg.sender] >= units, "units"); uint256 payout = calculator.output(units);
        balances[msg.sender] -= units; (bool ok,) = msg.sender.call{value: payout}(""); require(ok, "send");
    }
}
