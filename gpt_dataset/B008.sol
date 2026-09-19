// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign008V2 {
    address payable public immutable treasury;

    constructor(address payable t) {
        require(t != address(0), "zero");
        treasury = t;
    }

    receive() external payable {}

    function forward() external {
        uint256 amount = address(this).balance;
        (bool ok,) = treasury.call{value: amount}("");
        require(ok, "send");
    }
}
