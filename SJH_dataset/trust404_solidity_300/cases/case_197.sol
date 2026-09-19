// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0407 {
    mapping(address => uint256) public credits;
    bool private busy;
    receive() external payable { credits[msg.sender] += msg.value; }
    function settlePosition(uint256 amount) external {
        require(!busy && credits[msg.sender] >= amount, "denied");
        busy = true; credits[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        busy = false;
    }
}
