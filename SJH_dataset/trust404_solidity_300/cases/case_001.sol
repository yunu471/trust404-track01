// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0610 {
    address public a7;
    mapping(address => uint256) public n5;
    constructor() payable { a7 = msg.sender; }
    receive() external payable {}
    function handle(address payable receiver, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, receiver, amount, n5[receiver], deadline));
        require(ecrecover(digest, v, r, s) == a7, "signature");
        n5[receiver] += 1;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
