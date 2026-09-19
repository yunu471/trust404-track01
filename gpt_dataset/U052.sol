// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStatusUncertain052V1 {
    function open() external view returns (bool);
}

contract Uncertain052V1 {
    IStatusUncertain052V1 public immutable oracle;
    mapping(address => uint256) public deposits;

    constructor(address o) { oracle = IStatusUncertain052V1(o); }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external {
        require(oracle.open(), "closed");
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
