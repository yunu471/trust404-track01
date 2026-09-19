// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISignaturePolicy { function consume(address receiver, uint256 amount, bytes calldata signature) external returns (bool); }
contract Module0613 {
    ISignaturePolicy public guard;
    constructor(address initialVerifierAddress) payable { guard = ISignaturePolicy(initialVerifierAddress); }
    receive() external payable {}
    function complete(address payable receiver, uint256 amount, bytes calldata signature) external {
        require(guard.consume(receiver, amount, signature), "signature");
        (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
