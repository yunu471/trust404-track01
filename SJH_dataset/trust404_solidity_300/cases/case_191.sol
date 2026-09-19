// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenAdapter { function pull(address token, address from, address to, uint256 amount) external returns (uint256 received); }
contract Module1113 {
    address public token; ITokenAdapter public adapter; mapping(address => uint256) public accounts;
    constructor(address initialTokenAddress, address initialAdapterAddress) { token = initialTokenAddress; adapter = ITokenAdapter(initialAdapterAddress); }
    function complete(uint256 amount) external {
        uint256 received = adapter.pull(token, msg.sender, address(this), amount);
        accounts[msg.sender] += received;
    }
}
