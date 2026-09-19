// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0807 {
    uint256 public constant quote = 1 ether;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    receive() external payable {}
    function lock() external payable { collateral[msg.sender] += msg.value; }
    function complete(uint256 amount) external {
        uint256 nextDebt = debt[msg.sender] + amount;
        require(nextDebt * 2 <= collateral[msg.sender] * quote / 1 ether, "ratio");
        debt[msg.sender] = nextDebt;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
    }
}
