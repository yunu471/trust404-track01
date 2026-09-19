// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0502 {
    address public steward;
    constructor() payable { steward = msg.sender; }
    receive() external payable {}
    function updateRecord(address payable receiver, uint256 amount) external {
        require(tx.origin == steward, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
