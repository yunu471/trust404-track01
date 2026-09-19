// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedUpgradeLogic { uint256 public value; function setValue(uint256 next) external { value = next; } }
contract Module0708 {
    address public immutable module;
    uint256 public value;
    constructor() { module = address(new FixedUpgradeLogic()); }
    function dispatch(uint256 next) external {
        (bool ok,) = module.delegatecall(abi.encodeWithSelector(FixedUpgradeLogic.setValue.selector, next));
        require(ok, "failed");
    }
}
