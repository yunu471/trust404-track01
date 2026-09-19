// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// owner가 컨트랙트 ETH를 recovery 주소로 이동시킬 수 있습니다. 실수 송금 복구용일 수도 있지만 사용자 예치금을 함께 보관한다면 자금 탈취 경로가 될 수 있어 용도만으로 판정하기 어렵습니다.
pragma solidity ^0.8.20;

contract EmergencyRescue {
    address public owner;
    address payable public recovery;

    constructor(address payable _recovery) {
        owner = msg.sender;
        recovery = _recovery;
    }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    receive() external payable {}

    function rescueEther(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "balance");
        (bool ok,) = recovery.call{value: amount}("");
        require(ok, "send");
    }
}
