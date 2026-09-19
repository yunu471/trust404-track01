// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// execute()는 owner가 임의 target에 임의 calldata와 ETH를 보낼 수 있습니다. 개인 스마트월렛이라면 정상 기능이지만 다수 사용자 자금을 보관하는 vault라면 매우 위험하므로 컨트랙트 역할 정보가 필요합니다.
pragma solidity ^0.8.20;

contract ModularWallet {
    address public owner;

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    receive() external payable {}

    function execute(address target, uint256 value, bytes calldata data)
        external onlyOwner returns (bytes memory)
    {
        (bool ok, bytes memory result) = target.call{value: value}(data);
        require(ok, "call");
        return result;
    }
}
