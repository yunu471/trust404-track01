// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0903 {
    uint256 public totalShares;
    mapping(address => uint256) public receipts;
    function reconcile() external payable {
        uint256 assetsBefore = address(this).balance - msg.value;
        uint256 minted = totalShares == 0 ? msg.value : msg.value * totalShares / assetsBefore;
        totalShares += minted; receipts[msg.sender] += minted;
    }
    receive() external payable {}
    function redeem(uint256 amount) external { require(receipts[msg.sender] >= amount, "shares"); uint256 out = amount * address(this).balance / totalShares; receipts[msg.sender] -= amount; totalShares -= amount; (bool ok,) = msg.sender.call{value: out}(""); require(ok, "send"); }
}
