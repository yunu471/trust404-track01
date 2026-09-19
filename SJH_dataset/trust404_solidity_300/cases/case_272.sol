// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0401 {
    mapping(address => uint256) public balances;
    receive() external payable { balances[msg.sender] += msg.value; }
    function handle(uint256 amount) external {
        require(balances[msg.sender] >= amount, "funds");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        balances[msg.sender] -= amount;
    }
}
