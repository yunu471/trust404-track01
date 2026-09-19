// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1901 {
    mapping(address => uint256) public collateral; mapping(address => uint256) public debt;
    function open(uint256 borrowed) external payable { collateral[msg.sender] += msg.value; debt[msg.sender] += borrowed; }
    function handle(address borrower, uint256 repaid) external payable { require(msg.value == repaid && debt[borrower] >= repaid, "repay"); debt[borrower] -= repaid; uint256 seized = collateral[borrower]; collateral[borrower] = 0; (bool ok,) = msg.sender.call{value: seized}(""); require(ok, "send"); }
}
