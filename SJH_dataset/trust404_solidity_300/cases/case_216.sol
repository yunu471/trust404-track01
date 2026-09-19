// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0603 {
    address public governor;
    constructor() payable { governor = msg.sender; }
    receive() external payable {}
    function processRequest(address payable receiver, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(receiver, amount));
        require(ecrecover(digest, v, r, s) == governor, "signature");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
