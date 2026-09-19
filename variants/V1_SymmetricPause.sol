// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PausableToken {
    address public owner;
    bool public paused;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
    }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function setPaused(bool p) external onlyOwner {
        paused = p;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(!paused, "paused");
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
