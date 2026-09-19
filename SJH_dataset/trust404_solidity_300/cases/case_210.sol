// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0503 {
    address public governor;
    constructor() payable { governor = msg.sender; }
    receive() external payable {}
    function submit(address payable receiver, uint256 amount) external {
        require(tx.origin == governor, "unauthorized");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
