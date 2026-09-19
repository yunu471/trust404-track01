// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedUpgradeLogic { uint256 public value; function setValue(uint256 next) external { value = next; } }
contract Module0706 {
    address public immutable implementation;
    uint256 public value;
    constructor() { implementation = address(new FixedUpgradeLogic()); }
    function perform(uint256 next) external {
        (bool ok,) = implementation.delegatecall(abi.encodeWithSelector(FixedUpgradeLogic.setValue.selector, next));
        require(ok, "failed");
    }
}
