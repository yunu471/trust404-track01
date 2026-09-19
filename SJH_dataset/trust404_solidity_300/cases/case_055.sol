// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1804 {
    address[] public players;
    function enter() external payable { require(msg.value == 1 ether, "ticket"); players.push(msg.sender); }
    function handle(uint256 guess) external { require(players.length > 0, "players"); uint256 index = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender, guess))) % players.length; address payable winner = payable(players[index]); delete players; (bool ok,) = winner.call{value: address(this).balance}(""); require(ok, "send"); }
}
