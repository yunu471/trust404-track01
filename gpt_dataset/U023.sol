// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IHookUncertain023V2 {
    function validate(address from, address to, uint256 amount) external view returns (bool);
}

contract Uncertain023V2 {
    IHookUncertain023V2 public hook;
    mapping(address => uint256) public balanceOf;
    constructor(address h, uint256 supply) {
        hook = IHookUncertain023V2(h);
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external {
        require(hook.validate(msg.sender, to, amount), "rejected");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
