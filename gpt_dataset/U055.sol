// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IHookUncertain055V4 {
    function validate(address from, address to, uint256 amount) external view returns (bool);
}

contract Uncertain055V4 {
    IHookUncertain055V4 public hook;
    mapping(address => uint256) public balanceOf;
    constructor(address h, uint256 supply) {
        hook = IHookUncertain055V4(h);
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external {
        require(hook.validate(msg.sender, to, amount), "rejected");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
