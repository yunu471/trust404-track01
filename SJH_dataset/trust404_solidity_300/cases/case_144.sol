// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1402 {
    address public steward;
    constructor() payable { steward = msg.sender; }
    function dispatch(address payable receiver, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 id = keccak256(abi.encode(receiver, amount)); require(ecrecover(id, v, r, s) == steward, "proof");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
