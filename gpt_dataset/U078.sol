// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain078V2 {
    address public admin;
    uint256 public feeBps;
    uint256 public constant MAX_FEE_BPS = 350;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        admin = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }

    function setFee(uint256 value) external onlyAdmin {
        require(value <= MAX_FEE_BPS, "cap");
        feeBps = value;
    }
}
