// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISettlementRouter { function settle(address account, uint256 amount) external returns (bool); }
contract Module0411 {
    ISettlementRouter public router;
    mapping(address => uint256) public balances;
    constructor(address initialRouteAddress) { router = ISettlementRouter(initialRouteAddress); }
    receive() external payable { balances[msg.sender] += msg.value; }
    function executeAction(uint256 amount) external {
        require(balances[msg.sender] >= amount, "funds");
        require(router.settle(msg.sender, amount), "settlement");
        balances[msg.sender] -= amount;
    }
}
