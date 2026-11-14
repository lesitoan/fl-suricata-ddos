"""Host viewer lifecycle with mocked processes; no Docker/training/network."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controller import Controller,LabError
import tensorboard_service as service


class TensorBoardTests(unittest.TestCase):
    def test_viewer_job_works_without_docker_or_fl_and_rejects_extra_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            control=Controller(Path(folder),start_monitor=False)
            with (patch.object(control,'refresh_docker'),
                  patch.object(control,'_require_docker',side_effect=AssertionError('No Docker')),
                  patch('controller.start_tensorboard',return_value=service.URL) as launch,
                  patch('threading.Thread.start')):
                result=control.submit({'action':'tensorboard.start'})
                job=next(item for item in control.jobs if item['id']==result['job'])
                self.assertEqual(job['resources'],['tensorboard'])
                with self.assertRaises(LabError):control.submit({'action':'session.new'})
                control._work(job)
                self.assertEqual(job['status'],'complete');launch.assert_called_once()
                self.assertEqual(job['url'],service.URL)
                with self.assertRaises(LabError):control.submit({'action':'tensorboard.start','port':9999})

    def test_existing_managed_viewer_reused_and_unknown_port_not_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with patch.object(service,'ready',return_value=True),patch.object(service.subprocess,'Popen') as launch:
                self.assertEqual(service.start(root),service.URL);launch.assert_not_called()
            with patch.object(service,'ready',return_value=False),patch.object(service,'port_open',return_value=True),patch.object(service.subprocess,'Popen') as launch:
                with self.assertRaises(RuntimeError):service.start(root)
                launch.assert_not_called()

    def test_launcher_uses_fixed_host_script_and_records_actual_viewer_pid(self):
        import os
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            python=root/('runtime/tensorboard/venv/Scripts/python.exe' if os.name=='nt' else 'runtime/tensorboard/venv/bin/python')
            python.parent.mkdir(parents=True);python.write_bytes(b'fixture only')
            (root/'runtime/tensorboard/status.json').write_text('{"pid":456}')
            process=Mock(pid=123);process.poll.return_value=None
            with (patch.object(service,'ready',side_effect=[False,False,True]) as health,
                  patch.object(service,'port_open',return_value=False),
                  patch.object(service.subprocess,'Popen',return_value=process) as launch,
                  patch.object(service.time,'sleep')):
                self.assertEqual(service.start(root),service.URL)
                arguments=launch.call_args.args[0]
                self.assertEqual(arguments,[str(python),'-B',str(root/'tools/tensorboard/serve.py')])
                self.assertEqual(health.call_args.args,(root,))
                self.assertEqual((root/'runtime/tensorboard/server.pid').read_text(),'456')
                self.assertFalse(launch.call_args.kwargs.get('shell',False))


if __name__=='__main__':unittest.main()
