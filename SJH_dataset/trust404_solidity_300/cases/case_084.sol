// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuthority { function canSend(address caller, address origin, address receiver, uint256 amount) external view returns (bool); }
contract Module0513 {
    IAuthority public guard;
    constructor(address initialRulesAddress) payable { guard = IAuthority(initialRulesAddress); }
    receive() external payable {}
    function handle(address payable receiver, uint256 amount) external {
        require(guard.canSend(msg.sender, tx.origin, receiver, amount), "unauthorized");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
