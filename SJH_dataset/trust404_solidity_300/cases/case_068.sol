// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0404 {
    mapping(address => uint256) public positions;
    receive() external payable { positions[msg.sender] += msg.value; }
    function complete(uint256 amount) external {
        require(positions[msg.sender] >= amount, "funds");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        positions[msg.sender] -= amount;
    }
}
