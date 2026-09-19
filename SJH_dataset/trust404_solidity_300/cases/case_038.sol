// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0501 {
    address public owner;
    constructor() payable { owner = msg.sender; }
    receive() external payable {}
    function complete(address payable receiver, uint256 amount) external {
        require(tx.origin == owner, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
