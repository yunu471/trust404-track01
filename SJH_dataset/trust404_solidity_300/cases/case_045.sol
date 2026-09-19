// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0410 {
    mapping(address => uint256) public b2;
    bool private l1;
    receive() external payable { b2[msg.sender] += msg.value; }
    function synchronize(uint256 amount) external {
        require(!l1 && b2[msg.sender] >= amount, "denied");
        l1 = true; b2[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        l1 = false;
    }
}
