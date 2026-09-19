// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrictToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1109 {
    IStrictToken public reserveAsset; mapping(address => uint256) public positions;
    constructor(address initialTokenAddress) { reserveAsset = IStrictToken(initialTokenAddress); }
    function perform(uint256 amount) external { require(reserveAsset.transferFrom(msg.sender, address(this), amount), "receive"); positions[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(positions[msg.sender] >= amount, "funds"); positions[msg.sender] -= amount; require(reserveAsset.transfer(msg.sender, amount), "send"); }
}
