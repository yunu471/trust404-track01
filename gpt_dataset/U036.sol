// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStatusUncertain036V0 {
    function open() external view returns (bool);
}

contract Uncertain036V0 {
    IStatusUncertain036V0 public immutable oracle;
    mapping(address => uint256) public deposits;

    constructor(address o) { oracle = IStatusUncertain036V0(o); }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external {
        require(oracle.open(), "closed");
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
