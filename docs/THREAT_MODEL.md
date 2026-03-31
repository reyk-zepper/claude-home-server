# Threat Model

This document describes the trust boundaries, attack surface, mitigations, and
accepted residual risks for claude-home-server.

---

## System actors

| Actor | Trust level | Description |
|-------|-------------|-------------|
| Claude Code (operator) | Trusted | The developer's workstation running Claude Code. Connects over SSH using a dedicated key pair. Assumed to act in good faith. |
| Claude (LLM) | Semi-trusted | Generates tool call parameters. May produce unexpected or malformed input due to hallucination. Not considered an adversary, but its output is treated as untrusted input. |
| MCP server process | Constrained | Runs as a dedicated `mcp-server` OS user with no sudo rights except through approved wrapper scripts. Reads config and secrets it needs; cannot modify its own permissions policy. |
| Docker Socket Proxy | Constrained | A Tecnativa container that acts as a whitelisting proxy for Docker API calls. Limits what the MCP process can instruct Docker to do. |
| Home Assistant | External service | Accepts REST API calls authenticated by a Long-Lived Access Token. Mutations are further validated by HAConfigValidator before reaching the API. |
| Plex Media Server | External service | Accepts REST API calls authenticated by a Plex token. |
| Ubuntu OS | Trusted platform | The underlying operating system. The MCP process has limited OS-level privileges by design. |

---

## Trust boundary diagram

```
+----------------------+
|   Developer          |
|   (Claude Code)      |
|   Trusted            |
+----------+-----------+
           |
           | SSH key authentication
           | authorized_keys: command= restriction
           |
+----------v-----------+        +--------------------+
|   SSH daemon         |        |  config/            |
|   (sshd, port 22)   |        |  server.yaml        |
|   OS-managed         |        |  permissions.yaml   |
+----------+-----------+        |  (root:mcp-server,  |
           |                    |  640 — not writable |
           | stdio              |  by mcp-server)     |
           |                    +--------------------+
+----------v-----------+                |
|  MCP Server process  +----------------+
|  (mcp-server user)   |
|  FastMCP + modules   |
+--+---+---+---+---+---+
   |   |   |   |   |
   |   |   |   |   +-----> /var/log/claude-home-server/audit.log
   |   |   |   |           (append-only, chattr +a recommended)
   |   |   |   |
   |   |   |   +---------> /var/backups/claude-home-server/
   |   |   |               (pre-change backups, critical tools only)
   |   |   |
   |   |   +-------------> sudo /usr/local/bin/mcp-* wrappers only
   |   |                   (sudoers: NOPASSWD for /usr/local/bin/mcp-*)
   |   |
   |   +-----------------> Docker Socket Proxy (localhost:2375)
   |                       |
   |                       +-> Docker daemon via whitelisted API only
   |
   +--> PathValidator -----> Allowed filesystem paths only
        HAConfigValidator --> HA REST API (localhost:8123)
        ComposeValidator  --> Filesystem writes (compose files)
```

---

## Attack vectors and mitigations

### A. Path traversal

**Threat:** Claude generates a file path containing `../` sequences, null bytes,
or symlinks pointing outside allowed directories (e.g., `../../../../etc/passwd`).

**Mitigations:**

1. `PathValidator.validate_or_raise()` calls `os.path.realpath()` exactly once
   to resolve the path. All comparison is done against the single resolved value,
   eliminating TOCTOU windows from multiple realpath calls.
2. Null bytes in paths raise `PathValidationError` immediately.
3. The hardcoded blocklist covers known sensitive locations (`/etc/shadow`,
   `/etc/sudoers`, `/root`, `/proc`, `/sys`, `/dev`). This list is not
   configurable.
4. Filename patterns (`*.pem`, `*.key`, `.env`, SSH key patterns) are blocked by
   basename matching.
5. Path segment rules block any path containing `.ssh` or `secrets` as a
   component, regardless of depth.
6. Default-deny: a path not in `filesystem.allowed_paths` is rejected even if
   it passes all other checks.

**Residual risk:** The allowlist must be carefully scoped. An operator who adds
`/` or `/etc` to `allowed_paths` negates the protection.

---

### B. Command injection

**Threat:** Tool parameters are incorporated into shell commands, allowing
injection of shell metacharacters (e.g., `; rm -rf /`).

**Mitigations:**

1. `safe_run()` in `src/utils/subprocess_safe.py` always uses `shell=False`.
   Arguments are passed as a list; the OS exec family is called directly. No
   shell interpreter is involved.
2. Pydantic input models (`src/safety/input_sanitizer.py`) enforce strict
   allowlists on every parameter that reaches a subprocess call:
   - Service names: `^[a-zA-Z0-9@._-]+$`
   - Container names: `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`
   - Package names: `^[a-z0-9][a-z0-9+\-.]+$` (Debian policy)
   - UFW rules: `^[a-zA-Z0-9.:/\-\s]+$`
3. The environment of every subprocess is replaced with `CLEAN_ENV` (a fixed
   minimal PATH plus locale variables). Parent-process environment variables —
   including any credentials injected via the SSH session — cannot reach child
   processes.
4. `safe_run_sudo()` validates that the wrapper script path starts with
   `/usr/local/bin/mcp-` before spawning. Any other path returns an error
   without executing.
5. All subprocess calls have a hard timeout (default 30 seconds) and output is
   capped at 1 MB per stream to prevent resource exhaustion.

**Residual risk:** Validation regexes must be kept in sync with the actual
argument format. A future tool that passes user-supplied data to a command in a
context the current regexes do not cover would need its own Pydantic model.

---

### C. YAML injection

**Threat:** Malicious YAML content submitted through `ha_edit_config`,
`ha_create_automation`, `docker_compose_edit`, or similar tools that write YAML
files could introduce dangerous directives.

**Mitigations for HA config (HAConfigValidator):**

1. `yaml.safe_load()` is used for parsing — no custom YAML tags execute code.
2. Top-level and platform-style `shell_command`, `command_line`, `python_script`,
   and `rest_command` directives are unconditionally blocked (critical violation).
3. `custom_components` references, `packages` directives, external
   `panel_iframe` URLs, and plaintext secrets trigger warnings returned to the
   operator.
4. Malformed YAML produces a critical validation error; nothing is written to
   disk or sent to the API.

**Mitigations for Compose files (ComposeValidator):**

1. `privileged: true`, `cap_add`, `network_mode: host`, `pid: host`,
   `ipc: host`, `devices`, and `sysctls` are critical violations that block the
   write.
2. Volume mounts to sensitive host paths (`/`, `/etc`, `/root`, `/proc`, `/sys`,
   `/dev`, `/var/run/docker.sock`) are critical violations.
3. Both the modern (no `version:`) and legacy (`version:` + `services:`) compose
   formats are handled; a malformed top-level structure is a critical violation.

**Residual risk:** The blocked-directive list covers known HA integration types
as of the implementation date. New HA integrations that execute code in novel
ways would need to be added to `HAConfigValidator.BLOCKED_DIRECTIVES`.

---

### D. Privilege escalation

**Threat:** The MCP process uses its OS-level access to gain capabilities beyond
what it is supposed to have (e.g., read `/etc/shadow`, write arbitrary system
files, interact with Docker as root).

**Mitigations:**

1. The MCP process runs as a dedicated `mcp-server` OS user with no shell login
   and limited home directory permissions.
2. `sudo` access is restricted to scripts whose paths start with
   `/usr/local/bin/mcp-`. These scripts are installed at deployment time with
   root ownership and `755` permissions so the `mcp-server` user cannot modify
   them. The sudoers entry uses `NOPASSWD` only for this specific prefix.
3. Docker daemon access goes through the Tecnativa Docker Socket Proxy rather
   than a direct socket mount or TCP connection. The proxy whitelist prevents
   the MCP process from running privileged containers or accessing the Docker
   API endpoints that could lead to host escape.
4. `config/permissions.yaml` is owned by `root:mcp-server` with mode `640`.
   The MCP process can read it but cannot modify its own permission policy.
5. PathValidator blocks access to `/etc/sudoers`, `/etc/sudoers.d`, and `/root`
   via the hardcoded blocklist.

**Residual risk:** The operator must correctly configure the sudoers file and
ensure the `mcp-*` wrapper scripts are tightly scoped to their intended
operations. A wrapper script that accepts arbitrary arguments could still be
exploited.

---

### E. Token theft

**Threat:** Home Assistant and Plex tokens are sensitive credentials. If they
appear in log files, tool output, or error messages, they could be exfiltrated.

**Mitigations:**

1. Tokens are stored in separate files (`token_file` paths), not in
   `server.yaml`. Files should be mode `640` or `600` owned by
   `root:mcp-server`.
2. `load_secret()` warns but does not block when permissions are wider than
   `0o600`. Operators are expected to act on the warning.
3. Tokens are never passed as MCP tool parameters. They are loaded inside the
   module implementation and passed directly to HTTP clients, never returning
   to tool output.
4. `AuditLogger._sanitize_params()` redacts parameter keys matching `token`,
   `password`, `secret`, `api_key`, `auth`, `authorization`, and `content`
   before writing to the audit log.
5. `OutputFilter` applies both key-based and inline-pattern filtering to every
   tool return value before it reaches Claude. Inline patterns cover
   `token = ...`, `password: ...`, Bearer headers, PEM key blocks, and AWS
   credential patterns.
6. `OutputFilter.filter_env_vars()` masks sensitive `KEY=VALUE` lines in any
   tool that dumps environment variables.

**Residual risk:** An operator who disables or replaces the OutputFilter, or who
logs raw HTTP response bodies through a custom sink, could expose tokens. The
fallback to `sys.stderr` for the audit log means startup errors (before the log
file is open) may appear in the SSH session log.

---

### F. Denial of service

**Threat:** Runaway or malicious tool calls consume excessive server resources
(CPU, memory, disk, or critical-operation rate).

**Mitigations:**

1. **CircuitBreaker (per-tool):** After 3 consecutive failures for a single tool
   the circuit opens and subsequent calls return `[BLOCKED]` immediately without
   execution.
2. **Burst rate limiter:** At most 5 `critical`-risk tool calls are allowed per
   5-minute sliding window. The window uses `time.monotonic()` and is not
   affected by clock adjustments. Non-critical tools are not rate-limited.
3. **Subprocess timeout:** Every subprocess call has a hard timeout (default 30
   seconds; 600 seconds for long operations). Processes that exceed the timeout
   are forcefully killed.
4. **Subprocess output cap:** Stdout and stderr are capped at 1 MB per stream.
5. **OutputFilter size cap:** Tool return values are truncated at 50,000 bytes
   before reaching Claude.
6. **Pydantic content length limits:** The `content` field in write operations
   is capped at 1,000,000 characters (1 MB); paths at 4,096 characters; log
   line counts at 10,000.

**Residual risk:** The circuit breaker is in-memory and resets on process
restart. A loop that restarts the SSH session on circuit open could still cause
per-session resource use. The burst limiter only covers `critical` tools; a
flood of `read`-level calls is not rate-limited.

---

### G. Server-Side Request Forgery (SSRF)

**Threat:** Tool parameters cause the MCP server to make HTTP requests to
internal network services that should not be reachable (e.g., cloud metadata
endpoints, internal APIs).

**Mitigations:**

1. `rest_command` is a blocked directive in `HAConfigValidator`. Any HA config
   file containing it is rejected before the write.
2. HTTP calls are hardcoded to the URLs configured in `server.yaml`
   (`services.homeassistant.url`, `services.plex.url`,
   `services.docker.socket_proxy`). Tool parameters do not supply HTTP URLs
   directly to the HTTP client.
3. The Docker Socket Proxy limits which Docker API endpoints are reachable,
   preventing the MCP process from using Docker's `--network host` or container
   networking to pivot to other services.
4. `panel_iframe` URLs in HA config that point to non-local addresses trigger a
   warning from `HAConfigValidator`, surfacing the issue to the operator before
   the config is written.

**Residual risk:** The Home Assistant instance itself can make outbound requests
after the MCP server writes a valid config. HAConfigValidator does not
fully sandbox what HA can do with a valid non-blocked config. Operators should
run HA in a network namespace or with outbound firewall rules if this is a
concern.

---

## Residual risks and accepted trade-offs

| Risk | Accepted | Rationale |
|------|----------|-----------|
| Operator misconfigures `allowed_paths` too broadly | Yes | Configuring the allowlist is the operator's responsibility. Documentation warns against adding root-level paths. |
| In-memory circuit breaker state is lost on process restart | Yes | The circuit breaker protects against runaway failures in a single session. Persistent state would require a database dependency that is out of scope for a simple home-server tool. |
| `moderate`-risk tools are auto-approved without human confirmation | Yes | These tools (e.g., container restart, HA entity toggle) are designed to be used frequently and their effects are reversible. Operators can override any tool to `elevated` via `permissions.yaml`. |
| Audit log falls back to stderr when log directory is not writable | Yes | This ensures the server can start in restricted environments. Operators must ensure the log directory is writable in production. |
| Backup files are stored unencrypted | Yes | The backup directory is on the same server and access-controlled by OS permissions. Encryption would require key management complexity that is out of scope. |
| The `mcp-server` user can read `config/server.yaml` which contains service URLs | Yes | URLs are not secrets. Tokens are in separate files. |
| New HA integration types that execute code may not be in the blocked-directive list | Partially | The validator covers all known code-execution directives. Operators should review `ha_edit_config` output and keep HA updated. |

---

## Security boundary diagram (detail)

```
INPUT VALIDATION BOUNDARY
=========================
Claude Code -> SSH -> MCP stdin
                        |
                        v
              Pydantic InputSanitizer
              (type, length, regex, null-byte checks)
                        |
                        v
              PermissionEngine
              (risk level, auto-approve, backup flag)
                        |
                        v
              CircuitBreaker
              (per-tool failure count, critical burst limit)
                        |
          +-------------+-------------+
          |                           |
    Read path                   Write path
    (no side effects)           (critical tools)
          |                           |
          v                       BackupManager
    safe_run()                  (backup before write)
    PathValidator                   |
    (read ops)                      v
          |                   ComposeValidator /
          |                   HAConfigValidator /
          |                   PathValidator
          |                   (write ops)
          |                         |
          |                   safe_run() / HTTP client
          |                         |
          +-------------+-----------+
                        |
              OutputFilter
              (sensitive key masking,
               inline pattern redaction,
               size cap)
                        |
                        v
              AuditLogger
              (sanitized params, result, duration)
                        |
                        v
              MCP response -> Claude
```
