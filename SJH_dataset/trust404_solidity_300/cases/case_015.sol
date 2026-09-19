// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0506 {
    address public owner;
    constructor() payable { owner = msg.sender; }
    receive() external payable {}
    function processRequest(address payable receiver, uint256 amount) external {
        require(msg.sender == owner, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
