// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0508 {
    address public governor;
    constructor() payable { governor = msg.sender; }
    receive() external payable {}
    function executeAction(address payable receiver, uint256 amount) external {
        require(msg.sender == governor, "unauthorized");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
