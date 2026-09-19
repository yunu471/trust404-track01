// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1410 {
    address public a7; mapping(bytes32 => bool) public r2;
    constructor() payable { a7 = msg.sender; }
    function synchronize(address payable receiver, uint256 amount, uint256 sourceNonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 id = keccak256(abi.encode(address(this), block.chainid, receiver, amount, sourceNonce));
        require(!r2[id] && ecrecover(id, v, r, s) == a7, "proof"); r2[id] = true;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
