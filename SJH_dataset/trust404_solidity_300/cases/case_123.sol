// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAssetRegistry { function userLiability(address vault) external view returns (uint256); }
contract Module2412 {
    address public steward; IAssetRegistry public registry;
    constructor(address initialBookAddress) { steward = msg.sender; registry = IAssetRegistry(initialBookAddress); }
    receive() external payable {}
    function finalizeOperation() external { require(msg.sender == steward, "denied"); uint256 liabilities = registry.userLiability(address(this)); uint256 amount = address(this).balance - liabilities; (bool ok,) = payable(steward).call{value: amount}(""); require(ok, "send"); }
}
