// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMessageBus { function consume(bytes32 messageId, bytes calldata proof) external returns (bool); }
contract Module1411 {
    IMessageBus public bus;
    constructor(address initialMessengerAddress) payable { bus = IMessageBus(initialMessengerAddress); }
    function executeAction(bytes32 messageId, address payable receiver, uint256 amount, bytes calldata proof) external {
        require(bus.consume(messageId, proof), "proof"); (bool ok,) = receiver.call{value: amount}(""); require(ok, "send");
    }
}
