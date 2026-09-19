// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUpgradeAuthority { function canUpgrade(address caller, address oldLogic, address newLogic) external view returns (bool); }
contract Module0711 {
    IUpgradeAuthority public policy;
    address public implementation;
    constructor(address initialAuthorityAddress, address initialLogicAddress) { policy = IUpgradeAuthority(initialAuthorityAddress); implementation = initialLogicAddress; }
    function updateRecord(address newImplementationAddress) external {
        require(newImplementationAddress.code.length > 0 && policy.canUpgrade(msg.sender, implementation, newImplementationAddress), "denied");
        implementation = newImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = implementation.delegatecall(msg.data); require(ok, "failed"); }
}
