// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0408 {
    mapping(address => uint256) public accounts;
    bool private locked;
    receive() external payable { accounts[msg.sender] += msg.value; }
    function applyUpdate(uint256 amount) external {
        require(!locked && accounts[msg.sender] >= amount, "unauthorized");
        locked = true; accounts[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        locked = false;
    }
}
