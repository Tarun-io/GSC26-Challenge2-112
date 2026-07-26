import sys
import csv
import json
import argparse
from pathlib import Path
from typing import List, Dict, Tuple

sys.path.insert(0, str(Path(__file__).parent))
from yaml_parser import YamlTribunal

def normalize_finding(finding: Dict) -> Tuple[str, str]:
    return (finding.get('from', ''), finding.get('to', ''))

def findings_match(predicted: Tuple, ground_truth: Tuple, tolerance: int = 1) -> bool:
    pred_from, pred_to = predicted
    gt_from, gt_to = ground_truth

    def parse(s):
        if ':' not in s:
            return s, 0
        parts = s.rsplit(':', 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return s, 0

    pred_from_file, pred_from_line = parse(pred_from)
    pred_to_file, pred_to_line = parse(pred_to)
    gt_from_file, gt_from_line = parse(gt_from)
    gt_to_file, gt_to_line = parse(gt_to)

    def strip_split(path: str) -> str:
        parts = path.split('/')
        if parts and parts[0] in ('train', 'validation', 'test'):
            return '/'.join(parts[1:])
        return path

    from_file_match = strip_split(pred_from_file) == strip_split(gt_from_file)
    to_file_match = strip_split(pred_to_file) == strip_split(gt_to_file)

    if not (from_file_match and to_file_match):
        return False

    from_line_match = abs(pred_from_line - gt_from_line) <= tolerance
    to_line_match = abs(pred_to_line - gt_to_line) <= tolerance

    return from_line_match and to_line_match

def evaluate_sample(predictions: List[Dict], ground_truth_vulns: List[Dict]) -> Dict:
    pred_tuples = [normalize_finding(p) for p in predictions]
    gt_tuples = [normalize_finding(g) for g in ground_truth_vulns]

    matched_gt = set()
    matched_pred = set()

    for i, pred in enumerate(pred_tuples):
        for j, gt in enumerate(gt_tuples):
            if j not in matched_gt and findings_match(pred, gt):
                matched_gt.add(j)
                matched_pred.add(i)
                break

    tp = len(matched_gt)
    fp = len(pred_tuples) - len(matched_pred)
    fn = len(gt_tuples) - len(matched_gt)

    return {
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'matched': [(pred_tuples[i], gt_tuples[j])
                    for i, j in zip(sorted(matched_pred), sorted(matched_gt))
                    if i < len(pred_tuples) and j < len(gt_tuples)],
        'missed': [gt_tuples[j] for j in range(len(gt_tuples)) if j not in matched_gt],
        'false_positives': [pred_tuples[i] for i in range(len(pred_tuples)) if i not in matched_pred]
    }

def run_real_validation(dataset_root: Path):
    train_csv = dataset_root / 'train.csv'
    untrusted_csv = dataset_root / 'untrusted_data.csv'
    train_dir = dataset_root / 'train'

    if not train_csv.exists():
        sys.exit(1)

    with open(train_csv) as f:
        rows = list(csv.DictReader(f))

    total_tp = total_fp = total_fn = 0
    missed_details = []
    fp_details = []

    for row in rows:
        sample_id = row['sample_id']
        ground_truth = json.loads(row['vulnerabilities'])

        workflow_file = train_dir / 'workflows' / f'{sample_id}.yml'
        if not workflow_file.exists():
            workflow_file = train_dir / 'workflows' / f'{sample_id}.yaml'
        if not workflow_file.exists():
            continue

        try:
            tribunal = YamlTribunal(
                file_path=str(workflow_file),
                untrusted_csv=str(untrusted_csv),
                dataset_base=str(train_dir),
                competition_root=str(dataset_root)
            )
            tribunal.run_inspection()
            predictions = tribunal.component_findings
        except Exception:
            predictions = []

        result = evaluate_sample(predictions, ground_truth)
        total_tp += result['tp']
        total_fp += result['fp']
        total_fn += result['fn']

        if result['fn'] > 0:
            missed_details.append({
                'sample_id': sample_id,
                'missed': result['missed'],
                'our_predictions': [normalize_finding(p) for p in predictions]
            })

        if result['fp'] > 0:
            fp_details.append({
                'sample_id': sample_id,
                'false_positives': result['false_positives']
            })

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    print(f"TP: {total_tp} | FP: {total_fp} | FN: {total_fn}")
    print(f"Precision: {precision:.1%} | Recall: {recall:.1%} | F1: {f1:.1%}")

    if missed_details:
        for m in missed_details[:5]:
            print(f"FN ({m['sample_id']}): {m['missed']}")
    if fp_details:
        for f in fp_details[:5]:
            print(f"FP ({f['sample_id']}): {f['false_positives']}")

def run_synthetic_tests():
    tests_dir = Path(__file__).parent.parent / 'tests' / 'synthetic'
    untrusted_csv = Path(__file__).parent.parent / 'competition' / 'untrusted_data.csv'

    test_cases = [
        {'name': 'Direct workflow injection', 'file': 'direct_workflow.yml', 'expected_findings': 1, 'expected_to_line': 17},
        {'name': 'ENV_TO_RUN injection', 'file': 'env_to_run.yml', 'expected_findings': 1},
        {'name': 'Direct action injection', 'file': 'direct_action.yml', 'expected_findings': 1},
        {'name': 'Safe workflow', 'file': 'safe.yml', 'expected_findings': 0}
    ]

    passed = failed = 0
    for tc in test_cases:
        workflow_file = tests_dir / tc['file']
        if not workflow_file.exists():
            continue

        try:
            tribunal = YamlTribunal(
                file_path=str(workflow_file),
                untrusted_csv=str(untrusted_csv),
                dataset_base=str(tests_dir),
                competition_root=str(tests_dir)
            )
            import io
            from contextlib import redirect_stdout
            f = io.StringIO()
            with redirect_stdout(f):
                tribunal.run_inspection()

            n_found = len(tribunal.component_findings)
            if n_found == tc['expected_findings']:
                passed += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    print(f"Synthetic Tests: {passed} passed, {failed} failed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--synthetic', action='store_true')
    parser.add_argument('--dataset-root', type=str)
    args = parser.parse_args()

    if args.synthetic:
        run_synthetic_tests()
    elif args.dataset_root:
        run_real_validation(Path(args.dataset_root))