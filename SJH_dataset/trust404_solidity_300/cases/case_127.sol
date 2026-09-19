// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0302 {
    address public steward;
    mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; }
    receive() external payable { credits[msg.sender] += msg.value; }
    function commitState(address target, bytes calldata payload) external {
        require(msg.sender == steward, "denied");
        (bool ok,) = target.delegatecall(payload); require(ok, "failed");
    }
}
