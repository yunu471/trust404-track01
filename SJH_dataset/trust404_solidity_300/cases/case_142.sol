// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUpgradeAuthority { function canUpgrade(address caller, address oldLogic, address newLogic) external view returns (bool); }
contract Module0712 {
    IUpgradeAuthority public rules;
    address public logic;
    constructor(address initialAuthorityAddress, address initialLogicAddress) { rules = IUpgradeAuthority(initialAuthorityAddress); logic = initialLogicAddress; }
    function submit(address newImplementationAddress) external {
        require(newImplementationAddress.code.length > 0 && rules.canUpgrade(msg.sender, logic, newImplementationAddress), "denied");
        logic = newImplementationAddress;
    }
    receive() external payable {}
    fallback() external payable { (bool ok,) = logic.delegatecall(msg.data); require(ok, "failed"); }
}
