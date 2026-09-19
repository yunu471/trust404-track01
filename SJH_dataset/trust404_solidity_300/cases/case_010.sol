// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedUpgradeLogic { uint256 public value; function setValue(uint256 next) external { value = next; } }
contract Module0707 {
    address public immutable logic;
    uint256 public value;
    constructor() { logic = address(new FixedUpgradeLogic()); }
    function handle(uint256 next) external {
        (bool ok,) = logic.delegatecall(abi.encodeWithSelector(FixedUpgradeLogic.setValue.selector, next));
        require(ok, "failed");
    }
}
