// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0607 {
    address public steward;
    mapping(address => uint256) public sequence;
    constructor() payable { steward = msg.sender; }
    receive() external payable {}
    function routeValue(address payable receiver, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, receiver, amount, sequence[receiver], deadline));
        require(ecrecover(digest, v, r, s) == steward, "signature");
        sequence[receiver] += 1;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
