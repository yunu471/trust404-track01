// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1406 {
    address public owner; mapping(bytes32 => bool) public processed;
    constructor() payable { owner = msg.sender; }
    function submit(address payable receiver, uint256 amount, uint256 sourceNonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 id = keccak256(abi.encode(address(this), block.chainid, receiver, amount, sourceNonce));
        require(!processed[id] && ecrecover(id, v, r, s) == owner, "proof"); processed[id] = true;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
