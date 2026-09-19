// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceUncertain077V1 {
    function quote(uint256 units) external view returns (uint256);
}

contract Uncertain077V1 {
    IPriceUncertain077V1 public immutable oracle;
    mapping(address => uint256) public units;
    constructor(address o) { oracle = IPriceUncertain077V1(o); }

    function redeem(uint256 amount) external {
        require(units[msg.sender] >= amount, "units");
        uint256 payout = oracle.quote(amount);
        units[msg.sender] -= amount;
        require(address(this).balance >= payout, "liquidity");
        (bool ok,) = payable(msg.sender).call{value: payout}("");
        require(ok, "send");
    }

    receive() external payable {}
}
