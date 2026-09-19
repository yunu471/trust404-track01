// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain064V3 {
    address public admin;
    address public implementation;

    constructor(address impl) {
        admin = msg.sender;
        implementation = impl;
    }
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }

    function upgradeTo(address impl) external onlyAdmin {
        require(impl != address(0), "zero");
        implementation = impl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
