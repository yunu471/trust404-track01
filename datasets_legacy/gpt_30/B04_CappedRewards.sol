// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 관리자 발행 기능이 있지만 코드상 HARD_CAP을 넘을 수 없고 발행 대상과 양이 이벤트로 기록됩니다.
pragma solidity ^0.8.20;

contract CappedRewards {
    address public owner;
    uint256 public totalSupply;
    uint256 public constant HARD_CAP = 10_000_000 ether;
    mapping(address => uint256) public balanceOf;
    event RewardMinted(address indexed to, uint256 amount);

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function mintReward(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero");
        require(totalSupply + amount <= HARD_CAP, "cap");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit RewardMinted(to, amount);
    }
}
