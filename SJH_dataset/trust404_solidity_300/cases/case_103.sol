// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0510 {
    address public a7;
    constructor() payable { a7 = msg.sender; }
    receive() external payable {}
    function routeValue(address payable receiver, uint256 amount) external {
        require(msg.sender == a7, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
