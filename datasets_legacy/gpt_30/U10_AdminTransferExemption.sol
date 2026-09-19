// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// pause 상태에서도 admin은 전송할 수 있습니다. 운영상 유동성 관리 목적일 수 있지만 일반 사용자와 관리자 사이에 비대칭 권한이 있어 악용 가능성이 있으므로 추가 맥락이 필요합니다.
pragma solidity ^0.8.20;

contract AdminTransferExemption {
    address public admin;
    bool public paused;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        admin = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }

    function setPaused(bool value) external onlyAdmin {
        paused = value;
    }

    function transfer(address to, uint256 amount) external {
        require(!paused || msg.sender == admin, "paused");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
