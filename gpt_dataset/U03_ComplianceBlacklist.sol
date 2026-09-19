// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// 관리자가 특정 주소의 전송을 막을 수 있어 악용하면 선택적 동결이 가능하지만 규제 준수형 토큰에서도 쓰이는 구조입니다. 프로젝트 정책과 관리자 통제가 없으면 의도를 확정할 수 없습니다.
pragma solidity ^0.8.20;

contract ComplianceBlacklist {
    address public compliance;
    mapping(address => bool) public blocked;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        compliance = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyCompliance() { require(msg.sender == compliance, "compliance"); _; }

    function setBlocked(address user, bool value) external onlyCompliance {
        blocked[user] = value;
    }

    function transfer(address to, uint256 amount) external {
        require(!blocked[msg.sender] && !blocked[to], "blocked");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
