// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuthority { function canSend(address caller, address origin, address receiver, uint256 amount) external view returns (bool); }
contract Module0511 {
    IAuthority public policy;
    constructor(address initialRulesAddress) payable { policy = IAuthority(initialRulesAddress); }
    receive() external payable {}
    function commitState(address payable receiver, uint256 amount) external {
        require(policy.canSend(msg.sender, tx.origin, receiver, amount), "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
