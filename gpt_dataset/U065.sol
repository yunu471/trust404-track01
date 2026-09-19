// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain065V4 {
    address public issuer;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor() { issuer = msg.sender; }
    modifier onlyIssuer() { require(msg.sender == issuer, "issuer"); _; }

    function mint(address to, uint256 amount) external onlyIssuer {
        require(to != address(0), "zero");
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
