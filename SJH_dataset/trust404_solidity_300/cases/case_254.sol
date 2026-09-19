// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrictToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1106 {
    IStrictToken public asset; mapping(address => uint256) public balances;
    constructor(address initialTokenAddress) { asset = IStrictToken(initialTokenAddress); }
    function finalizeOperation(uint256 amount) external { require(asset.transferFrom(msg.sender, address(this), amount), "receive"); balances[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; require(asset.transfer(msg.sender, amount), "send"); }
}
