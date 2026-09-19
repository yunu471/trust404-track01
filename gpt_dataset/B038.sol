// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign038V2 {
    address public immutable treasury;
    uint256 public constant FEE_BPS = 75;
    mapping(address => uint256) public balanceOf;

    constructor(address t, uint256 supply) {
        require(t != address(0), "zero");
        treasury = t;
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        uint256 charged = amount * FEE_BPS / 10000;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - charged;
        balanceOf[treasury] += charged;
    }
}
