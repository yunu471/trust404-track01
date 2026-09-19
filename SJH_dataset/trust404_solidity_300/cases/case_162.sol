// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0409 {
    mapping(address => uint256) public positions;
    bool private activeCall;
    receive() external payable { positions[msg.sender] += msg.value; }
    function processRequest(uint256 amount) external {
        require(!activeCall && positions[msg.sender] >= amount, "denied");
        activeCall = true; positions[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        activeCall = false;
    }
}
