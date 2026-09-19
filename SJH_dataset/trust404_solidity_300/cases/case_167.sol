// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1407 {
    address public steward; mapping(bytes32 => bool) public consumed;
    constructor() payable { steward = msg.sender; }
    function settlePosition(address payable receiver, uint256 amount, uint256 sourceNonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 id = keccak256(abi.encode(address(this), block.chainid, receiver, amount, sourceNonce));
        require(!consumed[id] && ecrecover(id, v, r, s) == steward, "proof"); consumed[id] = true;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
