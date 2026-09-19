// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISignaturePolicy { function consume(address receiver, uint256 amount, bytes calldata signature) external returns (bool); }
contract Module0612 {
    ISignaturePolicy public rules;
    constructor(address initialVerifierAddress) payable { rules = ISignaturePolicy(initialVerifierAddress); }
    receive() external payable {}
    function reconcile(address payable receiver, uint256 amount, bytes calldata signature) external {
        require(rules.consume(receiver, amount, signature), "signature");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
