// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IHookUncertain071V0 {
    function validate(address from, address to, uint256 amount) external view returns (bool);
}

contract Uncertain071V0 {
    IHookUncertain071V0 public hook;
    mapping(address => uint256) public balanceOf;
    constructor(address h, uint256 supply) {
        hook = IHookUncertain071V0(h);
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external {
        require(hook.validate(msg.sender, to, amount), "rejected");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
