// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0403 {
    mapping(address => uint256) public accounts;
    receive() external payable { accounts[msg.sender] += msg.value; }
    function reconcile(uint256 amount) external {
        require(accounts[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        accounts[msg.sender] -= amount;
    }
}
