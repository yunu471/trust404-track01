// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain042V1 {
    address public bridge;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(address b) { bridge = b; }
    modifier onlyBridge() { require(msg.sender == bridge, "bridge"); _; }

    function bridgeMint(address to, uint256 amount) external onlyBridge {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function bridgeBurn(address from, uint256 amount) external onlyBridge {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
}
