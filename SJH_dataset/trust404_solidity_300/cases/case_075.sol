// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0803 {
    uint256 public referenceValue = 1 ether;
    mapping(address => uint256) public collateral;
    receive() external payable {}
    function setReference(uint256 next) external { referenceValue = next; }
    function lock() external payable { collateral[msg.sender] += msg.value; }
    function perform(uint256 amount) external {
        require(amount <= collateral[msg.sender] * referenceValue / 2 ether, "ratio");
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
    }
}
