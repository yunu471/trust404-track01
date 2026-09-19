// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0905 {
    uint256 public totalShares;
    mapping(address => uint256) public s8;
    function updateRecord() external payable {
        uint256 assetsBefore = address(this).balance - msg.value;
        uint256 minted = totalShares == 0 ? msg.value : msg.value * totalShares / assetsBefore;
        totalShares += minted; s8[msg.sender] += minted;
    }
    receive() external payable {}
    function redeem(uint256 amount) external { require(s8[msg.sender] >= amount, "shares"); uint256 out = amount * address(this).balance / totalShares; s8[msg.sender] -= amount; totalShares -= amount; (bool ok,) = msg.sender.call{value: out}(""); require(ok, "send"); }
}
