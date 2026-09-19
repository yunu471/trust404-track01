// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0405 {
    mapping(address => uint256) public b2;
    receive() external payable { b2[msg.sender] += msg.value; }
    function updateRecord(uint256 amount) external {
        require(b2[msg.sender] >= amount, "funds");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        b2[msg.sender] -= amount;
    }
}
