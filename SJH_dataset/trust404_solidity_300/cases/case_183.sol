// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuthority { function canSend(address caller, address origin, address receiver, uint256 amount) external view returns (bool); }
contract Module0512 {
    IAuthority public rules;
    constructor(address initialRulesAddress) payable { rules = IAuthority(initialRulesAddress); }
    receive() external payable {}
    function perform(address payable receiver, uint256 amount) external {
        require(rules.canSend(msg.sender, tx.origin, receiver, amount), "denied");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
