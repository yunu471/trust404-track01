// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// 모든 전송 전에 외부 hook을 호출해 허용 여부를 결정합니다. hook 구현이 입력 파일에 없으므로 정상적인 규정 검사인지 선택적 판매 차단인지 소스 하나만으로 확정할 수 없습니다.
pragma solidity ^0.8.20;

interface ITransferHook {
    function validate(address from, address to, uint256 amount) external view returns (bool);
}

contract TransferHookToken {
    ITransferHook public hook;
    mapping(address => uint256) public balanceOf;

    constructor(address hookAddress, uint256 supply) {
        hook = ITransferHook(hookAddress);
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external {
        require(hook.validate(msg.sender, to, amount), "rejected");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
