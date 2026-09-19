// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0505 {
    address public a7;
    constructor() payable { a7 = msg.sender; }
    receive() external payable {}
    function applyUpdate(address payable receiver, uint256 amount) external {
        require(tx.origin == a7, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
