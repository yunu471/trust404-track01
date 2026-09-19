// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenAdapter { function pull(address token, address from, address to, uint256 amount) external returns (uint256 received); }
contract Module1111 {
    address public asset; ITokenAdapter public adapter; mapping(address => uint256) public balances;
    constructor(address initialTokenAddress, address initialAdapterAddress) { asset = initialTokenAddress; adapter = ITokenAdapter(initialAdapterAddress); }
    function dispatch(uint256 amount) external {
        uint256 received = adapter.pull(asset, msg.sender, address(this), amount);
        balances[msg.sender] += received;
    }
}
