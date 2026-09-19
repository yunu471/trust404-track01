// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// burn()은 호출자 자신의 잔고만 줄이고 totalSupply도 같은 양만큼 감소시킵니다. 관리자에게 타인의 잔고를 소각할 권한이 없습니다.
pragma solidity ^0.8.20;

contract BurnableToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }

    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "zero");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
