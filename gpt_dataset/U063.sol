// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrategyUncertain063V2 {
    function deposit() external payable;
    function withdraw(uint256 amount, address to) external;
}

contract Uncertain063V2 {
    address public manager;
    IStrategyUncertain063V2 public strategy;
    constructor(address s) {
        manager = msg.sender;
        strategy = IStrategyUncertain063V2(s);
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
