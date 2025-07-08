#!/usr/bin/env python3
"""
Main scanner script - wrapper for multi_scanner.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanners'))

from multi_scanner import main

if __name__ == "__main__":
    main()
