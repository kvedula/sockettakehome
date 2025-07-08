#!/usr/bin/env python3
"""
Test runner script - wrapper for test_complete.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tests'))

from test_complete import main

if __name__ == "__main__":
    main()
