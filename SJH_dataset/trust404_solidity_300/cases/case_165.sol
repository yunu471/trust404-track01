// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISignaturePolicy { function consume(address receiver, uint256 amount, bytes calldata signature) external returns (bool); }
contract Module0611 {
    ISignaturePolicy public policy;
    constructor(address initialVerifierAddress) payable { policy = ISignaturePolicy(initialVerifierAddress); }
    receive() external payable {}
    function dispatch(address payable receiver, uint256 amount, bytes calldata signature) external {
        require(policy.consume(receiver, amount, signature), "signature");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
