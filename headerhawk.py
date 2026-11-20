#!/usr/bin/env python3
"""Convenience shim so the tool can run without installing it.

    python headerhawk.py https://example.com
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from headerhawk.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
