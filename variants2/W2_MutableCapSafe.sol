// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovernedCeiling {
    address public owner;
    uint256 public totalSupply;
    uint256 public cap = 1_000_000e18;
    uint256 public constant ABSOLUTE_MAX = 2_000_000e18;
    mapping(address => uint256) public balanceOf;

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function setCap(uint256 newCap) external onlyOwner {
        require(newCap <= ABSOLUTE_MAX, "too high");
        cap = newCap;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        require(totalSupply + amount <= cap, "cap exceeded");
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
