// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// transferFrom()은 모든 호출자에 대해 allowance를 검사하고 차감합니다. 관리자 예외나 우회 경로가 없습니다.
pragma solidity ^0.8.20;

contract SelfAllowanceToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 supply) { balanceOf[msg.sender] = supply; }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(balanceOf[from] >= amount, "balance");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
