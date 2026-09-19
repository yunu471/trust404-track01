// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0509 {
    address public custodian;
    constructor() payable { custodian = msg.sender; }
    receive() external payable {}
    function finalizeOperation(address payable receiver, uint256 amount) external {
        require(msg.sender == custodian, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
