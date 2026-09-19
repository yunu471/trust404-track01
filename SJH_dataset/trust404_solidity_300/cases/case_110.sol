// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedLogic { uint256 public value; function store(uint256 next) external { value = next; } }
contract Module0308 {
    address public immutable module;
    uint256 public value;
    constructor() { module = address(new FixedLogic()); }
    function updateRecord(uint256 next) external {
        (bool ok,) = module.delegatecall(abi.encodeWithSelector(FixedLogic.store.selector, next));
        require(ok, "failed");
    }
}
