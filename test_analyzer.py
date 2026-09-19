import pathlib
import re
import tempfile
import unittest
from unittest.mock import patch

import analyzer
from validate_schema import validate_item

ROOT = pathlib.Path(__file__).parent


class ClassificationTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / 'case.sol'
            path.write_text(source, encoding='utf-8')
            result = analyzer.coerce_to_schema(analyzer.analyze_file(str(path)))
        errors = []
        validate_item(result, 0, errors)
        self.assertEqual(errors, [])
        self.assertTrue(result['reasons'])
        for evidence in result['evidence']:
            self.assertLessEqual(evidence['line'], source.count('\n') + 1)
        return result

    def test_public_samples(self):
        for path in sorted((ROOT / 'challenge_public').glob('*.sol')):
            with self.subTest(path=path.name):
                expected = 'BENIGN' if path.name.startswith(('P1_', 'P4_')) else 'MALICIOUS'
                self.assertEqual(self.analyze(path.read_text())['verdict'], expected)

    def test_filename_does_not_affect_classification(self):
        sources = [
            ROOT / 'challenge_public/P1_StandardToken.sol',
            ROOT / 'challenge_public/P2_HiddenMint.sol',
            ROOT / 'gpt_dataset/U004.sol',
            *[ROOT / 'gpt_dataset' / name for name in ['U002.sol', 'U003.sol', 'U012.sol', 'U016.sol']],
        ]
        with tempfile.TemporaryDirectory() as folder:
            for source in sources:
                expected = None
                for name in ['BENIGN.sol', 'MALICIOUS.sol', 'UNCERTAIN.sol', 'random_42.sol']:
                    with self.subTest(source=source.name, filename=name):
                        path = pathlib.Path(folder) / name
                        path.write_text(source.read_text(), encoding='utf-8')
                        result = analyzer.analyze_file(str(path))
                        self.assertEqual(result.pop('file'), name)
                        if expected is None:
                            expected = result
                        self.assertEqual(result, expected)

    def test_external_behavior(self):
        for name in ['U004', 'U005', 'U006', 'U007', 'U008']:
            with self.subTest(name=name):
                result = self.analyze((ROOT / 'gpt_dataset' / (name + '.sol')).read_text())
                self.assertEqual(result['verdict'], 'UNCERTAIN')
                self.assertTrue(result['evidence'])

    def test_fixed_proxy_needs_implementation(self):
        source = (ROOT / 'variants/V6_ImmutableProxy.sol').read_text()
        self.assertEqual(self.analyze(source)['verdict'], 'UNCERTAIN')

    def test_operational_uncertainty_and_identifier_renaming(self):
        for filename in ['U002.sol', 'U003.sol', 'U012.sol', 'U016.sol']:
            source = (ROOT / 'gpt_dataset' / filename).read_text()
            with self.subTest(filename=filename):
                self.assertEqual(self.analyze(source)['verdict'], 'UNCERTAIN')
                # 역할/정책/함수/계약 이름에 기대지 않고 같은 구조를 인식한다.
                identifiers = ['compliance', 'blocked', 'setBlocked', 'to', 'owner',
                               'recovery', 'rescue', 'guardian', 'frozen', 'setFrozen',
                               'admin', 'implementation', 'impl', 'upgradeTo',
                               'onlyCompliance', 'onlyOwner', 'onlyGuardian', 'onlyAdmin']
                mapping = {name: 'x%d' % i for i, name in enumerate(identifiers)}
                renamed = re.sub(r'\b\w+\b', lambda m: mapping.get(m[0], m[0]), source)
                renamed = re.sub(r'\bUncertain\w*\b', 'C', renamed)
                self.assertEqual(self.analyze(renamed)['verdict'], 'UNCERTAIN')

    def test_deny_policy_exceptions_remain_malicious(self):
        source = (ROOT / 'gpt_dataset/U002.sol').read_text()
        for condition in ['!blocked[msg.sender]',
                          '!blocked[msg.sender] && !blocked[to] || msg.sender == compliance']:
            with self.subTest(condition=condition):
                changed = source.replace('!blocked[msg.sender] && !blocked[to]', condition)
                self.assertEqual(self.analyze(changed)['verdict'], 'MALICIOUS')

    def test_unrestricted_proxy_upgrade_remains_malicious(self):
        source = (ROOT / 'gpt_dataset/U016.sol').read_text()
        source = source.replace('external onlyAdmin', 'external')
        self.assertEqual(self.analyze(source)['verdict'], 'MALICIOUS')

    def test_other_malicious_path_is_not_hidden_by_uncertainty(self):
        source = (ROOT / 'gpt_dataset/U002.sol').read_text()
        source = source[:source.rfind('}')] + '''
          function seize(address user) external onlyCompliance {
            balanceOf[user] = 0;
          }
        }'''
        self.assertEqual(self.analyze(source)['verdict'], 'MALICIOUS')

    def test_fixed_withdrawal_policy_has_no_admin_uncertainty(self):
        source = (ROOT / 'gpt_dataset/U012.sol').read_text()
        source = source.replace('function setFrozen(bool value) external onlyGuardian { frozen = value; }', '')
        self.assertEqual(self.analyze(source)['verdict'], 'BENIGN')

    def test_conflicting_dataset_examples_are_not_forced_to_uncertain(self):
        for filename, expected in [('U001.sol', 'MALICIOUS'), ('U009.sol', 'MALICIOUS'),
                                   ('U010.sol', 'MALICIOUS'), ('U014.sol', 'BENIGN')]:
            with self.subTest(filename=filename):
                self.assertEqual(self.analyze((ROOT / 'gpt_dataset' / filename).read_text())['verdict'], expected)

    def test_analysis_gaps(self):
        for source in [
            'import "Base.sol"; contract C {}',
            'contract Base {} contract C is Base {}',
            'contract C { function f() external { assembly { mstore(0, 1) } } }',
            'contract C { function f() external { assembly ("memory-safe") { mstore(0, 1) } } }',
        ]:
            with self.subTest(source=source):
                self.assertEqual(self.analyze(source)['verdict'], 'UNCERTAIN')

    def test_malformed_source(self):
        for source in ['contract C {', 'contract C { function f(] {} }',
                       'contract C {} /* unfinished', 'contract C { string x = "unfinished']:
            with self.subTest(source=source):
                self.assertEqual(self.analyze(source)['verdict'], 'UNCERTAIN')

    def test_comments_strings_and_abi_are_not_external_calls(self):
        source = '''contract C {
          // import "x"; assembly { oracle.open(); }
          function f() external pure returns (bytes memory) {
            return abi.encode("oracle.open() import assembly", uint256(1));
          }
        }'''
        self.assertEqual(self.analyze(source)['verdict'], 'BENIGN')

    def test_malicious_takes_priority(self):
        source = 'import "Missing.sol"; ' + (ROOT / 'challenge_public/P2_HiddenMint.sol').read_text()
        self.assertEqual(self.analyze(source)['verdict'], 'MALICIOUS')

    def test_detector_failure_is_uncertain_and_other_detectors_continue(self):
        with patch.object(analyzer, 'detect_uncapped_mint', autospec=True, side_effect=ValueError('test')):
            result = self.analyze('contract C { function f() external {} }')
            self.assertEqual(result['verdict'], 'UNCERTAIN')
            self.assertIn('detect_uncapped_mint', result['reasons'][0])
            source = (ROOT / 'challenge_public/P5_DelegatecallBackdoor.sol').read_text()
            self.assertEqual(self.analyze(source)['verdict'], 'MALICIOUS')

    def test_timeout_is_not_swallowed(self):
        for target in ['detect_uncapped_mint', 'parse_source']:
            with self.subTest(target=target):
                with patch.object(analyzer, target, side_effect=analyzer._AnalysisTimeout):
                    with self.assertRaises(analyzer._AnalysisTimeout):
                        self.analyze('contract C { function f() external {} }')

    def test_benign_and_malicious_dataset_regression(self):
        for path in sorted((ROOT / 'gpt_dataset').glob('*.sol')):
            if path.name[0] not in 'BM':
                continue
            with self.subTest(path=path.name):
                expected = 'BENIGN' if path.name[0] == 'B' else 'MALICIOUS'
                self.assertEqual(self.analyze(path.read_text())['verdict'], expected)


if __name__ == '__main__':
    unittest.main()
