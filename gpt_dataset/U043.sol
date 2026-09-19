// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Uncertain043V2 {
    address public governance;
    constructor(address g) { governance = g; }
    modifier onlyGovernance() { require(msg.sender == governance, "governance"); _; }
    receive() external payable {}

    function execute(address target, uint256 value, bytes calldata data) external onlyGovernance {
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call");
    }
}
