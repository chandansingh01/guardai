"""Vercel serverless entry point."""
import os
import sys

# Ensure the project root is on the path
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

from src.api.app import app
