// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0406 {
    mapping(address => uint256) public balances;
    bool private entered;
    receive() external payable { balances[msg.sender] += msg.value; }
    function submit(uint256 amount) external {
        require(!entered && balances[msg.sender] >= amount, "denied");
        entered = true; balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
        entered = false;
    }
}
