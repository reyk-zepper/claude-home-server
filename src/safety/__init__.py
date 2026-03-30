"""Safety layer for claude-home-server.

Exports the three primary security components used at every tool boundary:

- :class:`PathValidator` — filesystem path allowlist/blocklist enforcement
- :class:`PathValidationError` — raised by ``PathValidator.validate_or_raise``
- :class:`OutputFilter` — scrubs sensitive data from tool return values
"""
from __future__ import annotations

from src.safety.output_filter import OutputFilter
from src.safety.path_validator import PathValidationError, PathValidator

__all__ = [
    "OutputFilter",
    "PathValidationError",
    "PathValidator",
]
