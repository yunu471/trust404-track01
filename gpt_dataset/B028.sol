// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign028V2 {
    uint256 public constant DRIP = 12 ether;
    uint256 public constant WAIT = 3628;
    mapping(address => uint256) public lastClaim;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 reserve) { balanceOf[address(this)] = reserve; }

    function claim() external {
        require(block.timestamp >= lastClaim[msg.sender] + WAIT, "wait");
        require(balanceOf[address(this)] >= DRIP, "empty");
        lastClaim[msg.sender] = block.timestamp;
        balanceOf[address(this)] -= DRIP;
        balanceOf[msg.sender] += DRIP;
    }
}
