// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 소유자가 전체 전송을 일시 중지할 수 있지만 pause 상태에서는 소유자를 포함한 모든 주소에 같은 제한이 적용됩니다. 특정 사용자만 판매를 막는 비대칭 경로는 없습니다.
pragma solidity ^0.8.20;

contract SymmetricPauseToken {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }

    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setPaused(bool value) external onlyOwner {
        paused = value;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!paused, "paused");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
