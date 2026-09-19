// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedLogic { uint256 public value; function store(uint256 next) external { value = next; } }
contract Module0307 {
    address public immutable logic;
    uint256 public value;
    constructor() { logic = address(new FixedLogic()); }
    function complete(uint256 next) external {
        (bool ok,) = logic.delegatecall(abi.encodeWithSelector(FixedLogic.store.selector, next));
        require(ok, "failed");
    }
}
