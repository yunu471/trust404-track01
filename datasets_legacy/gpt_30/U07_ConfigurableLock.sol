// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// owner가 globalUnlock을 미래로 변경할 수 있어 사용자 출금을 장기간 지연시킬 수 있습니다. 정상적인 락업 관리인지 악의적인 자금 동결인지 정책 정보 없이 확정하기 어렵습니다.
pragma solidity ^0.8.20;

contract ConfigurableLock {
    address public owner;
    uint256 public globalUnlock;
    mapping(address => uint256) public deposits;

    constructor(uint256 unlockAt) {
        owner = msg.sender;
        globalUnlock = unlockAt;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setUnlock(uint256 newUnlock) external onlyOwner {
        globalUnlock = newUnlock;
    }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= globalUnlock, "locked");
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
