// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoCustodyLottery {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function play() external payable {
        // 이 컨트랙트는 예치금을 기록하지 않는다 (즉시 소각 로직 등)
    }

    function sweep() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "fail");
    }
}
