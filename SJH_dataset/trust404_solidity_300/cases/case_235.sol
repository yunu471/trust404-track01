// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISettlementRouter { function settle(address account, uint256 amount) external returns (bool); }
contract Module0413 {
    ISettlementRouter public router;
    mapping(address => uint256) public accounts;
    constructor(address initialRouteAddress) { router = ISettlementRouter(initialRouteAddress); }
    receive() external payable { accounts[msg.sender] += msg.value; }
    function routeValue(uint256 amount) external {
        require(accounts[msg.sender] >= amount, "insufficient");
        require(router.settle(msg.sender, amount), "settlement");
        accounts[msg.sender] -= amount;
    }
}
