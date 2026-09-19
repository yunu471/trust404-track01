// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedUpgradeLogic { uint256 public value; function setValue(uint256 next) external { value = next; } }
contract Module0709 {
    address public immutable engine;
    uint256 public value;
    constructor() { engine = address(new FixedUpgradeLogic()); }
    function reconcile(uint256 next) external {
        (bool ok,) = engine.delegatecall(abi.encodeWithSelector(FixedUpgradeLogic.setValue.selector, next));
        require(ok, "failed");
    }
}
