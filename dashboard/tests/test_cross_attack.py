"""Check cross-node dataset routing, result validation and offline API guards."""
import csv
import tempfile
import unittest
from pathlib import Path

from test_dataset_eval import Synthetic, save, sha
from controller import Controller, LabError
from dataset_eval import evaluate_cross, predictions_page


class CrossAttackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = Synthetic(self.root, 'a')
        self.source = Synthetic(self.root, 'b')
        config = self.target.config
        config['clients'].update(self.source.config['clients'])
        save(self.root/'config/fl/fedavg.json', config)
        self.job = self.root/'reports/dashboard/sessions/test/job'
        self.job.mkdir(parents=True)

    def worker(self, args, *, wrong_identity=False):
        self.assertEqual(args[args.index('--network')+1], 'none')
        mounts = [value for value in args if value.startswith('type=bind,')]
        datasets = [value for value in mounts if 'target=/input/' in value]
        self.assertEqual(datasets, [f'type=bind,source={self.root/self.source.own/"test.csv"},target=/input/test.csv,readonly'])
        self.assertIn(f'type=bind,source={self.root/self.target.local/"weights.npz"},target=/model/local/weights.npz,readonly', mounts)
        self.assertEqual(args[args.index('--local-hash')+1], sha(self.root/self.target.local/'weights.npz'))
        with (self.root/self.source.own/'test.csv').open(encoding='utf-8') as stream:
            rows = list(csv.DictReader(stream))
        with (self.job/'dataset/predictions.csv').open('w', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['test_row_index', 'row_uid', 'true_label',
                             'local_probability_attack', 'local_predicted_label',
                             'global_probability_attack', 'global_predicted_label'])
            for index in (2, 3):
                writer.writerow([index, 'wrong' if wrong_identity else rows[index]['row_uid'],
                                 1, .25, 0, .5, 1])

    def test_cross_attack_counts_and_artifact(self):
        result = evaluate_cross(self.root, 'a', 'b', self.job, self.worker)
        self.assertEqual((result['source_node'], result['node'], result['rows']), ('B', 'A', 2))
        self.assertEqual(result['models']['local']['fn'], 2)
        self.assertEqual(result['models']['global']['tp'], 2)
        control = Controller(self.root, start_monitor=False)
        control.session = 'test'
        control.jobs = [{'id': 'job', 'node': 'a', 'action': 'dataset.cross_attack',
                         'status': 'complete', 'folder': self.job.relative_to(self.root).as_posix(),
                         'dataset_summary': result}]
        path, _ = control.dataset_artifact('job')
        self.assertEqual(predictions_page(path, 'local', 'fn')['total'], 2)
        self.assertEqual(predictions_page(path, 'global', 'fn')['total'], 0)

    def test_rejects_foreign_identity_and_same_node(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            evaluate_cross(self.root, 'a', 'b', self.job, lambda args: self.worker(args, wrong_identity=True))
        self.assertFalse((self.job/'dataset/summary.json').exists())
        control = Controller(self.root, start_monitor=False)
        with self.assertRaises(LabError):
            control.submit({'action': 'dataset.cross_attack', 'node': 'a', 'source_node': 'a'})
