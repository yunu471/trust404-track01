// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedLogic { uint256 public value; function store(uint256 next) external { value = next; } }
contract Module0309 {
    address public immutable engine;
    uint256 public value;
    constructor() { engine = address(new FixedLogic()); }
    function submit(uint256 next) external {
        (bool ok,) = engine.delegatecall(abi.encodeWithSelector(FixedLogic.store.selector, next));
        require(ok, "failed");
    }
}
