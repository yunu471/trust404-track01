// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0606 {
    address public owner;
    mapping(address => uint256) public nonces;
    constructor() payable { owner = msg.sender; }
    receive() external payable {}
    function finalizeOperation(address payable receiver, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, receiver, amount, nonces[receiver], deadline));
        require(ecrecover(digest, v, r, s) == owner, "signature");
        nonces[receiver] += 1;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
