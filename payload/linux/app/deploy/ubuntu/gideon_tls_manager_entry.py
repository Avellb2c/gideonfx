#!/usr/bin/env python3
"""Isolated-mode entry: import only installed, root-owned application modules."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gideon_tls_manager import main

if __name__ == '__main__':
    main()
