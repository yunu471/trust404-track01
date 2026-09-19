// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedUpgradeLogic { uint256 public value; function setValue(uint256 next) external { value = next; } }
contract Module0710 {
    address public immutable i6;
    uint256 public value;
    constructor() { i6 = address(new FixedUpgradeLogic()); }
    function complete(uint256 next) external {
        (bool ok,) = i6.delegatecall(abi.encodeWithSelector(FixedUpgradeLogic.setValue.selector, next));
        require(ok, "failed");
    }
}
