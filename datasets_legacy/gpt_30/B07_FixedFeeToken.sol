// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 전송 수수료가 코드에 1%로 고정되어 있고 임의로 올리는 관리자 함수가 없습니다. 수수료 로직도 모든 사용자에게 동일하게 적용됩니다.
pragma solidity ^0.8.20;

contract FixedFeeToken {
    address public treasury;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply, address feeTreasury) {
        require(feeTreasury != address(0), "zero");
        treasury = feeTreasury;
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        uint256 fee = amount / 100;
        uint256 net = amount - fee;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += net;
        balanceOf[treasury] += fee;
        return true;
    }
}
