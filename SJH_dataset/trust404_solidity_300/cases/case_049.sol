// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRiskEngine { function seize(address borrower, uint256 repaid) external view returns (uint256); }
contract Module1912 {
    IRiskEngine public engine; mapping(address => uint256) public collateral; mapping(address => uint256) public debt;
    constructor(address initialRiskAddress) { engine = IRiskEngine(initialRiskAddress); }
    function open(uint256 borrowed) external payable { collateral[msg.sender] += msg.value; debt[msg.sender] += borrowed; }
    function finalizeOperation(address borrower, uint256 repaid) external payable { require(msg.value == repaid && debt[borrower] >= repaid, "repay"); uint256 seized = engine.seize(borrower, repaid); require(seized <= collateral[borrower], "collateral"); debt[borrower] -= repaid; collateral[borrower] -= seized; (bool ok,) = msg.sender.call{value: seized}(""); require(ok, "send"); }
}
