// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedLogic { uint256 public value; function store(uint256 next) external { value = next; } }
contract Module0310 {
    address public immutable i6;
    uint256 public value;
    constructor() { i6 = address(new FixedLogic()); }
    function settlePosition(uint256 next) external {
        (bool ok,) = i6.delegatecall(abi.encodeWithSelector(FixedLogic.store.selector, next));
        require(ok, "failed");
    }
}
