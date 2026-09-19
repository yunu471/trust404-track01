// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benign011V0 {
    address payable public immutable beneficiary;
    uint64 public immutable start;
    uint64 public immutable duration;
    uint256 public released;

    constructor(address payable b, uint64 d) payable {
        beneficiary = b;
        start = uint64(block.timestamp);
        duration = d;
    }

    function release() external {
        uint256 elapsed = block.timestamp > start + duration ? duration : block.timestamp - start;
        uint256 total = address(this).balance + released;
        uint256 vested = total * elapsed / duration;
        uint256 amount = vested - released;
        released += amount;
        (bool ok,) = beneficiary.call{value: amount}("");
        require(ok, "send");
    }
}
