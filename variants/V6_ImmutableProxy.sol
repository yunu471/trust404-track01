// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MinimalProxy {
    address public immutable implementation;

    constructor(address impl) {
        implementation = impl;
    }

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "fail");
    }
}
