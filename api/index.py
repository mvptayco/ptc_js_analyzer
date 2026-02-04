import os
import sys

# Add project root to sys.path so we can import app.py
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app import app
