// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 생성자에서만 총공급량이 만들어지고 이후 공급량을 늘리거나 타인의 잔고를 임의 변경하는 특권 경로가 없습니다.
pragma solidity ^0.8.20;

contract FixedSupplyToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
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
