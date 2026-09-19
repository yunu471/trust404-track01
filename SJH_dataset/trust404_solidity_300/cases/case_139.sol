// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0805 {
    uint256 public q4 = 1 ether;
    mapping(address => uint256) public collateral;
    receive() external payable {}
    function setReference(uint256 next) external { q4 = next; }
    function lock() external payable { collateral[msg.sender] += msg.value; }
    function dispatch(uint256 amount) external {
        require(amount <= collateral[msg.sender] * q4 / 2 ether, "ratio");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
    }
}
