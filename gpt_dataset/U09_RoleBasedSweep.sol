// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// operator가 임의 ERC20을 treasury로 sweep할 수 있습니다. 금고에 잘못 들어온 토큰 복구 기능일 수 있지만 사용자가 ERC20을 예치하는 서비스라면 자금 이동 권한이 됩니다.
pragma solidity ^0.8.20;

interface IERC20Lite {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RoleBasedSweep {
    address public operator;
    address public treasury;

    constructor(address _treasury) {
        operator = msg.sender;
        treasury = _treasury;
    }
    modifier onlyOperator() { require(msg.sender == operator, "operator"); _; }

    function sweep(address token, uint256 amount) external onlyOperator {
        require(IERC20Lite(token).transfer(treasury, amount), "transfer");
    }
}
