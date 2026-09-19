// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 소유자가 지정한 target과 calldata로 delegatecall을 실행하므로 컨트랙트의 스토리지와 자산 제어 로직을 임의 코드로 변경할 수 있는 백도어입니다.
pragma solidity ^0.8.20;

contract ArbitraryDelegate {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function deposit() external payable { deposits[msg.sender] += msg.value; }

    function runModule(address target, bytes calldata data) external onlyOwner {
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegate");
    }
}
