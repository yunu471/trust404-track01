// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1409 {
    address public custodian; mapping(bytes32 => bool) public finalized;
    constructor() payable { custodian = msg.sender; }
    function processRequest(address payable receiver, uint256 amount, uint256 sourceNonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 id = keccak256(abi.encode(address(this), block.chainid, receiver, amount, sourceNonce));
        require(!finalized[id] && ecrecover(id, v, r, s) == custodian, "proof"); finalized[id] = true;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
