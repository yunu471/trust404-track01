"""이유 타당성 회귀 검사: 점수를 자동 부여하지 않고 코드와 설명의 연결을 검증한다."""
import pathlib
import tempfile
import unittest

import analyzer

ROOT = pathlib.Path(__file__).parent


class ReasoningTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'case.sol'
            path.write_text(source)
            return analyzer.analyze_file(str(path))

    def sample(self, name):
        return self.analyze((ROOT / 'gpt_dataset' / name).read_text())

    def test_benign_allowance_explains_check_and_consumption(self):
        result = self.sample('B007.sol')
        reason = ' '.join(result['reasons'])
        self.assertEqual(result['verdict'], 'BENIGN')
        for fact in ['allowance[from][msg.sender] >= amount',
                     'allowance[from][msg.sender] -= amount',
                     'balanceOf[from] -= amount', 'balanceOf[to] += amount']:
            self.assertIn(fact, reason)
        self.assertTrue(result['evidence'])

    def test_actual_deposit_is_not_described_as_force_send(self):
        result = self.sample('B009.sol')
        reason = ' '.join(result['reasons'])
        self.assertEqual(result['verdict'], 'BENIGN')
        self.assertNotIn('강제 송금', reason)
        self.assertNotIn('예치 경로', reason)
        for fact in ['msg.sender == buyer', 'closed = true', 'seller.call']:
            self.assertIn(fact, reason)

    def test_force_send_assumption_still_applies_without_deposit(self):
        source = '''contract C { address owner;
          constructor() { owner = msg.sender; }
          function sweep() external {
            require(msg.sender == owner);
            (bool ok,) = owner.call{value: address(this).balance}("");
            require(ok);
          }
        }'''
        result = self.analyze(source)
        self.assertEqual(result['verdict'], 'BENIGN')
        self.assertIn('강제 송금', ' '.join(result['reasons']))

    def test_uncertain_external_policy_includes_affected_ledger(self):
        result = self.sample('U004.sol')
        reason = ' '.join(result['reasons'])
        self.assertEqual(result['verdict'], 'UNCERTAIN')
        for fact in ['대상 구현', 'oracle.open()', 'deposits[msg.sender] -= amount', 'value: amount']:
            self.assertIn(fact, reason)

    def test_symmetric_pause_agrees_with_contest_boundary(self):
        source = (ROOT / 'gpt_dataset/U012.sol').read_text()
        result = self.analyze(source)
        self.assertEqual(result['verdict'], 'BENIGN')
        self.assertIn('대칭적 가용성', ' '.join(result['reasons']))
        exempt = source.replace('require(!frozen, "frozen");',
                                'require(!frozen || msg.sender == guardian, "frozen");')
        self.assertEqual(self.analyze(exempt)['verdict'], 'MALICIOUS')

    def test_owner_exemption_explains_actual_approval_and_asset_effect(self):
        result = self.sample('M004.sol')
        reason = ' '.join(result['reasons'])
        self.assertEqual(result['verdict'], 'MALICIOUS')
        for fact in ['소유자', 'msg.sender != controller',
                     'allowance[from][msg.sender] >= amount', 'balanceOf[from] -= amount']:
            self.assertIn(fact, reason)
        self.assertNotIn('[allowance[from][msg.sender] >= amount] 검사 뒤', reason)

    def test_evidence_and_facts_follow_source_edits(self):
        source = (ROOT / 'gpt_dataset/B003.sol').read_text()
        changed = '\n\n\n' + source.replace('balanceOf', 'units')
        before, after = self.analyze(source), self.analyze(changed)
        self.assertIn('units[msg.sender]', ' '.join(after['reasons']))
        self.assertNotIn('balanceOf[', ' '.join(after['reasons']))
        self.assertEqual([e['line'] + 3 for e in before['evidence']],
                         [e['line'] for e in after['evidence']])

    def test_mutated_amount_is_not_described_as_checked_invariant(self):
        source = '''contract C {
          mapping(address => uint) public balance;
          function burn(uint amount) external {
            require(balance[msg.sender] >= amount);
            amount = amount * 2;
            balance[msg.sender] -= amount;
          }
        }'''
        result = self.analyze(source)
        self.assertNotIn('한도를 소비합니다', ' '.join(result['reasons']))

    def test_parameter_shadow_is_not_described_as_fixed_recipient(self):
        source = '''contract C {
          address immutable target;
          constructor(address recipient) { target = recipient; }
          function execute(address target, uint amount) external {
            (bool ok,) = target.call{value: amount}("");
            require(ok);
          }
        }'''
        result = self.analyze(source)
        self.assertNotIn('수령지 target는 immutable', ' '.join(result['reasons']))


if __name__ == '__main__':
    unittest.main()
