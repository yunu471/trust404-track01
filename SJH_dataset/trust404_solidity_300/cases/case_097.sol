// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0507 {
    address public steward;
    constructor() payable { steward = msg.sender; }
    receive() external payable {}
    function synchronize(address payable receiver, uint256 amount) external {
        require(msg.sender == steward, "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
