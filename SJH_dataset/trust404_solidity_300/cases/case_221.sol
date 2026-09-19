// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1408 {
    address public governor; mapping(bytes32 => bool) public executed;
    constructor() payable { governor = msg.sender; }
    function applyUpdate(address payable receiver, uint256 amount, uint256 sourceNonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 id = keccak256(abi.encode(address(this), block.chainid, receiver, amount, sourceNonce));
        require(!executed[id] && ecrecover(id, v, r, s) == governor, "proof"); executed[id] = true;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
