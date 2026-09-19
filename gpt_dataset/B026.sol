// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign026V0 {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 pool) {
        owner = msg.sender;
        balanceOf[address(this)] = pool;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function distribute(address[] calldata users, uint256 each) external onlyOwner {
        uint256 need = users.length * each;
        require(balanceOf[address(this)] >= need, "pool");
        balanceOf[address(this)] -= need;
        for (uint256 j = 0; j < users.length; j++) {
            balanceOf[users[j]] += each;
        }
    }
}
