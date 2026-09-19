// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// ownerBurn()은 승인 없이 임의 보유자의 잔고를 소각합니다. 사용자가 스스로 소각하는 기능과 달리 관리자에게 일방적인 자산 제거 권한을 줍니다.
pragma solidity ^0.8.20;

contract PrivilegedBurnFrom {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function ownerBurn(address from, uint256 amount) external onlyOwner {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
}
