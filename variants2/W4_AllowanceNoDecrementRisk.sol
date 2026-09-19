// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LeakyApproval {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(allowance[from][msg.sender] >= value, "not allowed");
        require(balanceOf[from] >= value, "insufficient");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }
}
