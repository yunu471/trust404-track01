// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0609 {
    address public custodian;
    mapping(address => uint256) public serials;
    constructor() payable { custodian = msg.sender; }
    receive() external payable {}
    function perform(address payable receiver, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, receiver, amount, serials[receiver], deadline));
        require(ecrecover(digest, v, r, s) == custodian, "signature");
        serials[receiver] += 1;
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
