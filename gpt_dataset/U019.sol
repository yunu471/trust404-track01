// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain019V3 {
    address public owner;
    address payable public recovery;
    constructor(address payable r) {
        owner = msg.sender;
        recovery = r;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    receive() external payable {}

    function rescue(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "balance");
        (bool ok,) = recovery.call{value: amount}("");
        require(ok, "send");
    }
}
