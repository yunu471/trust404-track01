// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedLogic { uint256 public value; function store(uint256 next) external { value = next; } }
contract Module0306 {
    address public immutable implementation;
    uint256 public value;
    constructor() { implementation = address(new FixedLogic()); }
    function reconcile(uint256 next) external {
        (bool ok,) = implementation.delegatecall(abi.encodeWithSelector(FixedLogic.store.selector, next));
        require(ok, "failed");
    }
}
