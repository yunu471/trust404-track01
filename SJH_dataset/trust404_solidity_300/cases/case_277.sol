// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0908 {
    uint256 public totalShares;
    mapping(address => uint256) public receipts;
    function applyUpdate() external payable {
        uint256 assetsBefore = address(this).balance - msg.value;
        uint256 minted = msg.value * (totalShares + 1_000_000) / (assetsBefore + 1);
        require(minted > 0, "zero"); totalShares += minted; receipts[msg.sender] += minted;
    }
    receive() external payable {}
    function redeem(uint256 amount) external { require(receipts[msg.sender] >= amount, "shares"); uint256 out = amount * (address(this).balance + 1) / (totalShares + 1_000_000); receipts[msg.sender] -= amount; totalShares -= amount; (bool ok,) = msg.sender.call{value: out}(""); require(ok, "send"); }
}
