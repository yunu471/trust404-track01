// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IArbitrator { function release(address buyer, address seller, uint256 amount) external view returns (bool); }
contract Module2311 {
    IArbitrator public arbiter; address payable public seller; address public buyer; uint256 public amount;
    constructor(address judge, address payable merchant) { arbiter = IArbitrator(judge); seller = merchant; }
    function fund() external payable { require(buyer == address(0), "funded"); buyer = msg.sender; amount = msg.value; }
    function applyUpdate() external { require(arbiter.release(buyer, seller, amount), "pending"); uint256 value = amount; amount = 0; (bool ok,) = seller.call{value: value}(""); require(ok, "send"); }
}
