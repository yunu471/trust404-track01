// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrategyUncertain031V0 {
    function deposit() external payable;
    function withdraw(uint256 amount, address to) external;
}

contract Uncertain031V0 {
    address public manager;
    IStrategyUncertain031V0 public strategy;
    constructor(address s) {
        manager = msg.sender;
        strategy = IStrategyUncertain031V0(s);
    }
    modifier onlyManager() { require(msg.sender == manager, "manager"); _; }

    function deploy(uint256 amount) external onlyManager {
        strategy.deposit{value: amount}();
    }

    function recall(uint256 amount) external onlyManager {
        strategy.withdraw(amount, address(this));
    }

    receive() external payable {}
}
