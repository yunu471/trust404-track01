// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign012V1 {
    uint256 public constant DRIP = 11 ether;
    uint256 public constant WAIT = 3612;
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
