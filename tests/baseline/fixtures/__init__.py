"""Synthetic baseline fixtures for the persistence test suite.

Each builder is a pure function returning a deterministic
``BaselineRecord`` whose UUIDs are derived from ``uuid.uuid5``
seeds so the resulting record is byte-identical across runs. This
gives the determinism property tests (Properties 23-32) a stable
input space.
"""
