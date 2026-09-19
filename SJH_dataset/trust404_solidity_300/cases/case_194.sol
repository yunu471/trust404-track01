// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1807 {
    address[] public players; uint256 public nextWinner;
    function enter() external payable { require(msg.value == 1 ether, "ticket"); players.push(msg.sender); }
    function decorativeNumber() external view returns (uint256) { return uint256(block.prevrandao); }
    function complete() external { require(players.length > 0, "players"); uint256 index = nextWinner % players.length; nextWinner += 1; address payable winner = payable(players[index]); delete players; (bool ok,) = winner.call{value: address(this).balance}(""); require(ok, "send"); }
}
