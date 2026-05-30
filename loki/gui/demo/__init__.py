"""Synthetic demo data builders.

Synthetic instances are clearly labeled "(demo)" everywhere they surface
in the UI so they're never confused with output from a real extraction
pipeline (which doesn't exist yet).
"""

from loki.gui.demo.synthetic import build_demo_workspace

__all__ = ["build_demo_workspace"]
