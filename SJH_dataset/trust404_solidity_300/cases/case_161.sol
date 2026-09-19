// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAssetRegistry { function userLiability(address vault) external view returns (uint256); }
contract Module2411 {
    address public owner; IAssetRegistry public registry;
    constructor(address initialBookAddress) { owner = msg.sender; registry = IAssetRegistry(initialBookAddress); }
    receive() external payable {}
    function executeAction() external { require(msg.sender == owner, "denied"); uint256 liabilities = registry.userLiability(address(this)); uint256 amount = address(this).balance - liabilities; (bool ok,) = payable(owner).call{value: amount}(""); require(ok, "send"); }
}
