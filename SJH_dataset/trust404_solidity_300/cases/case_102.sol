// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUpgradeAuthority { function canUpgrade(address caller, address oldLogic, address newLogic) external view returns (bool); }
contract Module0713 {
    IUpgradeAuthority public guard;
    address public module;
    constructor(address initialAuthorityAddress, address initialLogicAddress) { guard = IUpgradeAuthority(initialAuthorityAddress); module = initialLogicAddress; }
    function settlePosition(address newImplementationAddress) external {
        require(newImplementationAddress.code.length > 0 && guard.canUpgrade(msg.sender, module, newImplementationAddress), "unauthorized");
        module = newImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = module.delegatecall(msg.data); require(ok, "failed"); }
}
