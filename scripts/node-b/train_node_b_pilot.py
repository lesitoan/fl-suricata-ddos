"""Local MLP training entry point for node B."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from train_mlp import main


if __name__ == '__main__':
    main('B', 'One seed, one recording day, and a UDP capture with time blocks; no real-time/FL generalization claim.', validation_only_default=True)
