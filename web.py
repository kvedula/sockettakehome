#!/usr/bin/env python3
"""
Web UI launcher script - wrapper for web_ui.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web'))

from web_ui import app

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
