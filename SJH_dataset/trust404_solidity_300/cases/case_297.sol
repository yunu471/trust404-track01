// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0804 {
    uint256 public mark = 1 ether;
    mapping(address => uint256) public collateral;
    receive() external payable {}
    function setReference(uint256 next) external { mark = next; }
    function lock() external payable { collateral[msg.sender] += msg.value; }
    function handle(uint256 amount) external {
        require(amount <= collateral[msg.sender] * mark / 2 ether, "ratio");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
    }
}
