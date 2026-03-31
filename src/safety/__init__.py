"""Safety layer for claude-home-server.

Exports the primary security components used at every tool boundary:

- :class:`PathValidator` — filesystem path allowlist/blocklist enforcement
- :class:`PathValidationError` — raised by ``PathValidator.validate_or_raise``
- :class:`OutputFilter` — scrubs sensitive data from tool return values
- :class:`ComposeValidator` — validates Docker Compose file content before apply
- :class:`HAConfigValidator` — validates HA YAML config for dangerous directives
"""
from __future__ import annotations

from src.safety.compose_validator import ComposeValidator
from src.safety.ha_config_validator import HAConfigValidator
from src.safety.output_filter import OutputFilter
from src.safety.path_validator import PathValidationError, PathValidator

__all__ = [
    "ComposeValidator",
    "HAConfigValidator",
    "OutputFilter",
    "PathValidationError",
    "PathValidator",
]
