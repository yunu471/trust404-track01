// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0605 {
    address public a7;
    constructor() payable { a7 = msg.sender; }
    receive() external payable {}
    function executeAction(address payable receiver, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(receiver, amount));
        require(ecrecover(digest, v, r, s) == a7, "signature");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
