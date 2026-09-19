// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISettlementRouter { function settle(address account, uint256 amount) external returns (bool); }
contract Module0412 {
    ISettlementRouter public router;
    mapping(address => uint256) public credits;
    constructor(address initialRouteAddress) { router = ISettlementRouter(initialRouteAddress); }
    receive() external payable { credits[msg.sender] += msg.value; }
    function finalizeOperation(uint256 amount) external {
        require(credits[msg.sender] >= amount, "funds");
        require(router.settle(msg.sender, amount), "settlement");
        credits[msg.sender] -= amount;
    }
}
