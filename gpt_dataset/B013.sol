// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign013V2 {
    address public owner;
    address public pendingOwner;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function proposeOwner(address next) external onlyOwner {
        require(next != address(0), "zero");
        pendingOwner = next;
    }

    function acceptOwner() external {
        require(msg.sender == pendingOwner, "pending");
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
