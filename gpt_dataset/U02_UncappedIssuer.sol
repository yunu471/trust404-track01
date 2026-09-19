// SPDX-License-Identifier: MIT
// LABEL: UNCERTAIN
//
// issuer가 상한 없이 토큰을 발행할 수 있어 강한 중앙화 위험이 있지만 발행 대상이 임의 주소이고 코드만으로 사기 의도인지 정상적인 스테이블코인/브리지 발행 모델인지 확정하기 어렵습니다.
pragma solidity ^0.8.20;

contract UncappedIssuer {
    address public issuer;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor() { issuer = msg.sender; }
    modifier onlyIssuer() { require(msg.sender == issuer, "issuer"); _; }

    function mint(address to, uint256 amount) external onlyIssuer {
        require(to != address(0), "zero");
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
