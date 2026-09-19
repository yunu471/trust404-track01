// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IShareMath { function previewDeposit(uint256 assets, uint256 holdings, uint256 supply) external view returns (uint256); }
contract Module0911 {
    IShareMath public calculator;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    constructor(address initialMathAddress) { calculator = IShareMath(initialMathAddress); }
    function executeAction() external payable {
        uint256 minted = calculator.previewDeposit(msg.value, address(this).balance - msg.value, totalShares);
        totalShares += minted; shares[msg.sender] += minted;
    }
    receive() external payable {}
}
