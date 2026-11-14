"""Host-only TensorBoard and metric exporter; no Docker commands or fitting."""
import argparse
import json
import signal
import sys
import time
import webbrowser
from pathlib import Path

from collector import Collector,CollectorLock,atomic_json

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once',action='store_true',help='Export saved metrics once without serving')
    parser.add_argument('--open',action='store_true')
    args = parser.parse_args()
    # Fixed local bind and output scope; no public exposure or arbitrary log paths.
    with CollectorLock(ROOT/'runtime/tensorboard/collector.lock'):
        collector = Collector(ROOT)
        stopped = False
        def stop(*unused):
            nonlocal stopped
            stopped = True
        signal.signal(signal.SIGTERM,stop)
        signal.signal(signal.SIGINT,stop)
        try:
            status = collector.sync()
            print(json.dumps(status),flush=True)
            if args.once: return
            from tensorboard import program
            board = program.TensorBoard()
            board.configure(argv=[None,'--logdir',str(collector.output),'--host','127.0.0.1',
                                  '--port','6006','--load_fast','false','--reload_interval','2'])
            url = board.launch()
            print('TensorBoard: '+url,flush=True)
            if args.open: webbrowser.open('http://127.0.0.1:6006/')
            while not stopped:
                collector.sync()
                time.sleep(2)
        finally:
            collector.close()
            atomic_json(ROOT/'runtime/tensorboard/status.json',
                        {'status':'stopped','updated_at':time.time(),'pid':__import__('os').getpid()})


if __name__=='__main__':main()
