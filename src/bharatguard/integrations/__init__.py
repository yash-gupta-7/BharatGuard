"""Sarvam SDK integration layer.

This is the ONLY subpackage in BharatGuard allowed to import `sarvamai`.
Core modules (models, normalization, detectors, policy, masking, core) must
never depend on this package or on `sarvamai`.
"""
