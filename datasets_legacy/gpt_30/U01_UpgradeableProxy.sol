// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// delegatecall 자체는 프록시 구조에 필요할 수 있지만 admin이 implementation을 교체할 수 있어 최종 동작은 현재 소스만으로 확정할 수 없습니다. 구현체와 업그레이드 거버넌스 검토가 필요합니다.
pragma solidity ^0.8.20;

contract UpgradeableProxy {
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
