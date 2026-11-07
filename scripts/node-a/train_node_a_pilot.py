"""Local MLP training entry point for node A."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from train_mlp import main


if __name__ == '__main__':
    main('A', 'One seed, one recording day, and a short SYN attack window per partition; no real-time/FL generalization claim.')
