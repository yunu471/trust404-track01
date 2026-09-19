// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0402 {
    mapping(address => uint256) public credits;
    receive() external payable { credits[msg.sender] += msg.value; }
    function dispatch(uint256 amount) external {
        require(credits[msg.sender] >= amount, "funds");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        credits[msg.sender] -= amount;
    }
}
