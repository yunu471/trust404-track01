// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILooseToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1101 {
    ILooseToken public asset; mapping(address => uint256) public balances;
    constructor(address initialTokenAddress) { asset = ILooseToken(initialTokenAddress); }
    function settlePosition(uint256 amount) external { asset.transferFrom(msg.sender, address(this), amount); balances[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; require(asset.transfer(msg.sender, amount), "send"); }
}
