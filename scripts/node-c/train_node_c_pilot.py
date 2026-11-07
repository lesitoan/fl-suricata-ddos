"""Local MLP training entry point for node C LDAP/BENIGN data."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from train_mlp import main


if __name__ == '__main__':
    main('C', 'Single recording day, separated LDAP-labelled capture windows, one seed; no FL, live LDAP-reflection or independent generalization claim.')
