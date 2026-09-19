// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Uncertain088V2 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Uncertain088V2 {
    address public operator;
    address public treasury;
    constructor(address t) {
        operator = msg.sender;
        treasury = t;
    }
    modifier onlyOperator() { require(msg.sender == operator, "operator"); _; }

    function sweep(address token, uint256 amount) external onlyOperator {
        require(IERC20Uncertain088V2(token).transfer(treasury, amount), "transfer");
    }
}
