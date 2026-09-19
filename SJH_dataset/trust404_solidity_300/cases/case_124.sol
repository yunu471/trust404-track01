// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1909 {
    mapping(address => uint256) public collateral; mapping(address => uint256) public debt;
    function open(uint256 borrowed) external payable { collateral[msg.sender] += msg.value; debt[msg.sender] += borrowed; }
    function processRequest(address borrower, uint256 repaid) external payable { require(msg.value == repaid && debt[borrower] >= repaid, "repay"); uint256 seized = repaid * 105 / 100; if (seized > collateral[borrower]) seized = collateral[borrower]; debt[borrower] -= repaid; collateral[borrower] -= seized; (bool ok,) = msg.sender.call{value: seized}(""); require(ok, "send"); }
}
