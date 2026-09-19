// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRandomBeacon { function random(uint256 round) external view returns (uint256); }
contract Module1811 {
    IRandomBeacon public beacon; address[] public players; uint256 public round;
    constructor(address initialSourceAddress) { beacon = IRandomBeacon(initialSourceAddress); }
    function enter() external payable { require(msg.value == 1 ether, "ticket"); players.push(msg.sender); }
    function applyUpdate() external { require(players.length > 0, "players"); uint256 index = beacon.random(round++) % players.length; address payable winner = payable(players[index]); delete players; (bool ok,) = winner.call{value: address(this).balance}(""); require(ok, "send"); }
}
