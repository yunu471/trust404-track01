// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign004V3 {
    mapping(address => uint256) public credit;

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount, "credit");
        credit[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
