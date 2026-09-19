// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 수익 수령 주소는 생성자에서 immutable로 고정되고 이후 관리자에 의해 교체되지 않습니다. 사용자의 개별 잔고를 임의로 조작하는 기능도 없습니다.
pragma solidity ^0.8.20;

contract ImmutableTreasury {
    address payable public immutable treasury;

    constructor(address payable _treasury) {
        require(_treasury != address(0), "zero");
        treasury = _treasury;
    }

    receive() external payable {}

    function forwardRevenue() external {
        uint256 amount = address(this).balance;
        (bool ok,) = treasury.call{value: amount}("");
        require(ok, "send");
    }
}
