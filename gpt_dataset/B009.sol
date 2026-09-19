// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign009V3 {
    address public immutable buyer;
    address payable public immutable seller;
    bool public closed;

    constructor(address payable s) {
        buyer = msg.sender;
        seller = s;
    }

    receive() external payable {
        require(msg.sender == buyer, "buyer");
        require(!closed, "closed");
    }

    function release() external {
        require(msg.sender == buyer && !closed, "buyer");
        closed = true;
        (bool ok,) = seller.call{value: address(this).balance}("");
        require(ok, "send");
    }

    function refund() external {
        require(msg.sender == buyer && !closed, "buyer");
        closed = true;
        (bool ok,) = payable(buyer).call{value: address(this).balance}("");
        require(ok, "send");
    }
}
