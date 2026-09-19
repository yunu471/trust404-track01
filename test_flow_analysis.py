"""흐름 규칙의 정상/위험 쌍 및 이름 변경 회귀 검증.

정답 파일은 테스트에서만 읽으며 analyzer에는 전달하지 않는다.
"""
import json
import pathlib
import re
import tempfile
import unittest

import analyzer
from validate_schema import validate_item

ROOT = pathlib.Path(__file__).parent
CASES = ROOT / 'SJH_dataset/trust404_solidity_300/cases'


class FlowTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / 'arbitrary.sol'
            path.write_text(source, encoding='utf-8')
            result = analyzer.analyze_file(str(path))
        errors = []
        validate_item(result, 0, errors)
        self.assertEqual(errors, [])
        self.assertFalse(any('분석에 실패' in r for r in result['reasons']), result)
        for evidence in result['evidence']:
            self.assertLessEqual(evidence['line'], source.count('\n') + 1)
        return result

    def verdict(self, source):
        return self.analyze(source)['verdict']

    def test_top_level_declarations_and_actual_immutable(self):
        source = '''contract C { address public x; uint public count;
          address public immutable fixedTarget;
          mapping(address => uint) public ledger;
          function f() external { uint local = 1; }
        }'''
        contract = analyzer.parse_source(source)[0]
        self.assertEqual({n for _, n, _ in contract.state_vars}, {'x', 'count', 'fixedTarget', 'ledger'})
        self.assertNotIn('immutable', analyzer.typ_immutable_check(contract, 'x'))
        self.assertIn('immutable', analyzer.typ_immutable_check(contract, 'fixedTarget'))

    def test_supply_cap_is_structure_not_name(self):
        source = '''contract C {
          address public actor; uint public quantity; uint constant maximum = 100;
          mapping(address => uint) public ledger;
          constructor() { actor = msg.sender; }
          function f(address recipient, uint n) external {
            require(msg.sender == actor);
            require(recipient != address(0) && quantity + n <= maximum);
            quantity += n; ledger[recipient] += n;
          }
        }'''
        self.assertEqual(self.verdict(source), 'BENIGN')
        self.assertEqual(self.verdict(source.replace('require(recipient != address(0) && quantity + n <= maximum);', '')), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('&& quantity', '|| quantity')), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('quantity += n;', 'quantity += n * 10;')), 'MALICIOUS')

    def test_deposit_drain_uses_value_and_ledger_not_names(self):
        source = (CASES / 'case_043.sol').read_text()
        self.assertEqual(self.verdict(source), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('balances[msg.sender] += msg.value;', '')), 'BENIGN')

    def test_external_policy_only_protects_related_effect(self):
        source = (CASES / 'case_024.sol').read_text()
        self.assertEqual(self.verdict(source), 'UNCERTAIN')
        self.assertEqual(self.verdict(source.replace('require(controller.approved(target, selector), "denied");', '')), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('controller.approved(target, selector)', 'controller.approved(address(0), selector)')), 'MALICIOUS')

    def test_guarded_and_unguarded_unchecked_debit(self):
        source = (CASES / 'case_085.sol').read_text()
        self.assertEqual(self.verdict(source), 'MALICIOUS')
        safe = source.replace('unchecked {', 'require(accounts[msg.sender] >= amount); unchecked {')
        self.assertEqual(self.verdict(safe), 'BENIGN')
        self.assertEqual(self.verdict((CASES / 'case_023.sol').read_text()), 'UNCERTAIN')

    def test_replay_protection_must_update_signed_nonce(self):
        source = (CASES / 'case_001.sol').read_text()
        self.assertEqual(self.verdict(source), 'BENIGN')
        self.assertEqual(self.verdict(source.replace('n5[receiver] += 1;', '')), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('n5[receiver] += 1;', 'n5[receiver] = 0;')), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('n5[receiver] += 1;', 'n5[receiver] += 0;')), 'MALICIOUS')

    def test_approval_is_not_ownership_transfer(self):
        source = (CASES / 'case_071.sol').read_text()
        self.assertEqual(self.verdict(source), 'BENIGN')
        self.assertEqual(self.verdict(source.replace('delete approved[id];', '')), 'MALICIOUS')

    def test_claim_marker_precedes_payout(self):
        source = (CASES / 'case_016.sol').read_text()
        self.assertEqual(self.verdict(source), 'BENIGN')
        self.assertEqual(self.verdict(source.replace('redeemed[msg.sender] = true;', '')), 'MALICIOUS')
        late = source.replace('redeemed[msg.sender] = true;', '').replace('require(ok, "send");', 'require(ok, "send"); redeemed[msg.sender] = true;')
        self.assertEqual(self.verdict(late), 'MALICIOUS')

    def test_value_reuse_requires_payable_batch_and_no_zero_guard(self):
        source = (CASES / 'case_003.sol').read_text()
        self.assertEqual(self.verdict(source), 'BENIGN')
        unsafe = source.replace('require(msg.value == 0, "value");', '')
        self.assertEqual(self.verdict(unsafe), 'MALICIOUS')
        self.assertEqual(self.verdict(unsafe.replace('external payable {\n        ', 'external {\n        ')), 'BENIGN')
        self.assertEqual(self.verdict((CASES / 'case_181.sol').read_text()), 'UNCERTAIN')

    def test_discarded_token_success_before_credit(self):
        source = (CASES / 'case_018.sol').read_text()
        self.assertEqual(self.verdict(source), 'MALICIOUS')
        checked = source.replace('x3.transferFrom(msg.sender, address(this), amount);', 'require(x3.transferFrom(msg.sender, address(this), amount));')
        self.assertEqual(self.verdict(checked), 'UNCERTAIN')

    def test_block_randomness_must_affect_payout(self):
        self.assertEqual(self.verdict((CASES / 'case_034.sol').read_text()), 'MALICIOUS')
        self.assertEqual(self.verdict((CASES / 'case_152.sol').read_text()), 'BENIGN')

    def test_share_issue_and_rounding_protection(self):
        source = (CASES / 'case_009.sol').read_text()
        self.assertEqual(self.verdict(source), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('totalShares += minted;', 'require(minted > 0); totalShares += minted;')), 'BENIGN')
        source = (CASES / 'case_132.sol').read_text()
        self.assertEqual(self.verdict(source), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('(units + 99) / 100', 'units / 100')), 'BENIGN')

    def test_liquidation_requires_full_repayment_for_full_collateral(self):
        source = (CASES / 'case_044.sol').read_text()
        self.assertEqual(self.verdict(source), 'MALICIOUS')
        self.assertEqual(self.verdict(source.replace('debt[borrower] >= repaid', 'debt[borrower] == repaid')), 'BENIGN')

    def test_escrow_buyer_confirmation(self):
        source = (CASES / 'case_070.sol').read_text()
        self.assertEqual(self.verdict(source), 'BENIGN')
        self.assertEqual(self.verdict(source.replace('msg.sender == seller && delivered', 'msg.sender == seller')), 'MALICIOUS')

    def test_sjh_regression_and_identifier_invariance(self):
        gold = json.loads((CASES.parent / 'answers/answers.json').read_text())
        for row in gold:
            with self.subTest(case=row['file']):
                source = (CASES / row['file']).read_text()
                result = self.verdict(source)
                self.assertIn(result, {row['verdict'], 'UNCERTAIN'})
                names = set()
                for contract in analyzer.parse_source(analyzer.strip_comments_and_strings(source)):
                    names.add(contract.name)
                    names.update(n for _, n, _ in contract.state_vars)
                    names.update(f.name for f in contract.functions if f.name not in {'receive', 'fallback'})
                    names.update(contract.modifiers)
                rename = {name: 'renamed_%d' % i for i, name in enumerate(sorted(names))}
                changed = re.sub(r'\b\w+\b', lambda m: rename.get(m[0], m[0]), source)
                self.assertEqual(self.verdict(changed), result)


if __name__ == '__main__':
    unittest.main()
