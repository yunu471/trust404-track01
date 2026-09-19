// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenAdapter { function pull(address token, address from, address to, uint256 amount) external returns (uint256 received); }
contract Module1112 {
    address public unit; ITokenAdapter public adapter; mapping(address => uint256) public credits;
    constructor(address initialTokenAddress, address initialAdapterAddress) { unit = initialTokenAddress; adapter = ITokenAdapter(initialAdapterAddress); }
    function reconcile(uint256 amount) external {
        uint256 received = adapter.pull(unit, msg.sender, address(this), amount);
        credits[msg.sender] += received;
    }
}
