"""Output filtering security component for claude-home-server.

Filters sensitive data from tool output before it is returned to Claude.
Covers three attack surfaces:

  1. Free-form text — regex patterns for inline credential leakage
  2. Structured dicts — recursive key-name matching (e.g. env dumps, JSON)
  3. KEY=VALUE env lists — covers ``os.environ``-style output and ``printenv``

Additionally enforces a hard output-size cap so that runaway tool output
cannot be used as a denial-of-service vector.

CRITICAL: This module must be applied to ALL tool return values, not only to
          outputs that are suspected to be sensitive. Defense-in-depth requires
          unconditional filtering.
"""
from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Sensitive key patterns — matched against dict key names and env var names.
# Order does not matter; all are checked.
# ---------------------------------------------------------------------------

SENSITIVE_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r".*password.*", re.IGNORECASE),
    re.compile(r".*secret.*", re.IGNORECASE),
    re.compile(r".*token.*", re.IGNORECASE),
    re.compile(r"^key$|.*[_\-.]key$|^key[_\-.].*|.*[_\-.]key[_\-.].*", re.IGNORECASE),
    re.compile(r".*credential.*", re.IGNORECASE),
    re.compile(r".*auth.*", re.IGNORECASE),
    re.compile(r".*api.?key.*", re.IGNORECASE),
    re.compile(r".*private.*", re.IGNORECASE),
]

# Replacement sentinel placed wherever a sensitive value was removed.
MASK: str = "***FILTERED***"

# ---------------------------------------------------------------------------
# Inline-text patterns — matched against the *value* of strings and text
# blobs, not the key name. These catch credentials embedded in prose output.
# ---------------------------------------------------------------------------

_INLINE_SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
    # Generic API keys: long alphanum strings after common prefixes
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(secret[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(auth[_-]?token\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(bearer\s+)\S+"),
    # PEM private key blocks
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    ),
    # AWS-style access key IDs and secret access keys
    re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*)\S+"),
]

_TRUNCATED_MARKER: str = "\n[TRUNCATED]"


class OutputFilter:
    """Filters sensitive data from tool output before returning to Claude.

    Instantiate once and reuse across tool calls; the object is stateless
    beyond the ``max_output_bytes`` configuration value.

    Args:
        max_output_bytes: Hard cap on output size in bytes.  Content
            exceeding this limit is truncated and a ``[TRUNCATED]`` marker
            is appended.  Defaults to 50 000 bytes.

    Example::

        flt = OutputFilter()
        safe_text = flt.filter_text(raw_output)
        safe_env  = flt.filter_env_vars(env_lines)
        safe_dict = flt.filter_dict(json_response)
    """

    def __init__(self, max_output_bytes: int = 50_000) -> None:
        self._max_bytes = max_output_bytes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter_text(self, text: str) -> str:
        """Filter sensitive inline patterns from text and truncate to the size cap.

        Applies all ``_INLINE_SENSITIVE_PATTERNS`` substitutions in order,
        replacing matched groups with ``MASK``, then delegates to
        :meth:`truncate`.

        Args:
            text: Raw string output from a tool.

        Returns:
            Filtered and possibly truncated string safe to return to Claude.
        """
        if not text:
            return text

        result = text
        for pattern in _INLINE_SENSITIVE_PATTERNS:
            # Replace only the captured value group where possible; fall back
            # to masking the entire match when there is no capturing group.
            if pattern.groups:
                result = pattern.sub(lambda m: m.group(1) + MASK, result)
            else:
                result = pattern.sub(MASK, result)

        return self.truncate(result)

    def filter_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively filter sensitive keys from a dict.

        The walk is depth-first.  Any key that matches
        :meth:`_is_sensitive_key` has its value replaced with ``MASK``.
        Nested dicts are filtered recursively; lists are walked and any
        dict elements within them are filtered too.

        Args:
            data: Arbitrary dict, possibly nested, as returned by a tool.

        Returns:
            New dict with identical structure but sensitive values masked.
        """
        return {k: self._filter_value(k, v) for k, v in data.items()}

    def filter_env_vars(self, env_list: list[str]) -> list[str]:
        """Filter ``KEY=VALUE`` lines where the key name is sensitive.

        Lines that do not conform to the ``KEY=VALUE`` format (e.g. blank
        lines, comments) are passed through unchanged so callers can still
        read non-sensitive env output without surprises.

        Args:
            env_list: List of strings in ``KEY=VALUE`` or ``KEY=`` format,
                as produced by ``os.environ`` serialisation or ``printenv``.

        Returns:
            List with the same length; sensitive values replaced by ``MASK``.
        """
        result: list[str] = []
        for line in env_list:
            if "=" in line:
                key, _, _value = line.partition("=")
                if self._is_sensitive_key(key.strip()):
                    result.append(f"{key}={MASK}")
                    continue
            result.append(line)
        return result

    def truncate(self, text: str) -> str:
        """Truncate *text* to ``max_output_bytes`` and append a marker.

        The truncation is performed on the UTF-8 byte representation to
        ensure the cap is a hard byte-level limit, not a character-count
        limit (which could be circumvented with multi-byte characters).

        Args:
            text: String to truncate.

        Returns:
            Original string if within the size limit, otherwise a truncated
            version with ``[TRUNCATED]`` appended.
        """
        encoded = text.encode("utf-8")
        if len(encoded) <= self._max_bytes:
            return text

        marker_bytes = _TRUNCATED_MARKER.encode("utf-8")
        keep = self._max_bytes - len(marker_bytes)
        # Decode with errors="ignore" so we don't split a multi-byte sequence
        # and produce an invalid string.
        truncated = encoded[:keep].decode("utf-8", errors="ignore")
        return truncated + _TRUNCATED_MARKER

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_sensitive_key(self, key: str) -> bool:
        """Return True if *key* matches any sensitive key pattern.

        Args:
            key: Dict key or env var name to test.

        Returns:
            True when *key* matches at least one pattern in
            ``SENSITIVE_KEY_PATTERNS``.
        """
        return any(pattern.fullmatch(key) for pattern in SENSITIVE_KEY_PATTERNS)

    def _filter_value(self, key: str, value: Any) -> Any:
        """Decide how to filter *value* based on *key* and value type.

        Args:
            key: The dict key associated with this value.
            value: The value to potentially filter.

        Returns:
            ``MASK`` when the key is sensitive, a recursively filtered dict
            when the value is itself a dict (regardless of key sensitivity),
            a walked list when the value is a list, or the original value
            for all other types.
        """
        if self._is_sensitive_key(key):
            return MASK

        if isinstance(value, dict):
            return self.filter_dict(value)

        if isinstance(value, list):
            return [
                self.filter_dict(item) if isinstance(item, dict)
                else self.filter_text(item) if isinstance(item, str)
                else item
                for item in value
            ]

        if isinstance(value, str):
            return self.filter_text(value)

        return value
