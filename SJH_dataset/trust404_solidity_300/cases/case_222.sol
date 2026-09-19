// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceFeed { function latest() external view returns (uint256 value, uint256 updatedAt); }
contract Module0813 {
    IPriceFeed public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    constructor(address initialFeedAddress) { oracle = IPriceFeed(initialFeedAddress); }
    receive() external payable {}
    function lock() external payable { collateral[msg.sender] += msg.value; }
    function synchronize(uint256 amount) external {
        (uint256 value,) = oracle.latest();
        require(debt[msg.sender] + amount <= collateral[msg.sender] * value / 2 ether, "ratio");
        debt[msg.sender] += amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send");
    }
}
