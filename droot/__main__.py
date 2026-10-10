"""
droot package entry point: python -m droot
"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
