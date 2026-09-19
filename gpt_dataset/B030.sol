// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign030V4 {
    uint256 public constant USER_CAP = 104 ether;
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        require(deposits[msg.sender] + msg.value <= USER_CAP, "cap");
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
