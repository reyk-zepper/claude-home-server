# Architecture

claude-home-server is a Python/FastMCP server that runs on a Ubuntu home server
and lets Claude Code manage Docker, Home Assistant, Plex, the OS, and the
filesystem. The process communicates exclusively over stdio through an SSH
session. There is no HTTP listener and no open network port on the MCP process
itself.

---

## High-level data flow

```
+-----------------+          SSH (stdio transport)          +---------------------------+
|   Claude Code   |  =====================================> |  claude-home-server (MCP) |
| (developer's    |  <=====================================  |  running as mcp-server    |
|  workstation)   |   JSON-RPC over stdin/stdout             |  on Ubuntu homeserver     |
+-----------------+                                         +---------------------------+
                                                                         |
                              +------------------------------------------+
                              |
            +-----------------+------------------+------------------+------------------+
            |                 |                  |                  |                  |
    +--------+-----+  +-------+------+  +--------+-----+  +--------+-----+  +---------+----+
    |  System (OS) |  | Docker       |  | Filesystem   |  | Home         |  | Plex         |
    |  systemctl   |  | socket proxy |  | (PathValid.) |  | Assistant    |  | Media Server |
    |  apt / ufw   |  | compose      |  |              |  | REST API     |  | REST API     |
    +--------------+  +--------------+  +--------------+  +--------------+  +--------------+
```

### SSH authorized_keys restriction

Claude Code connects using a dedicated SSH key. The `authorized_keys` entry on
the server restricts the session to a single command so the key cannot be used
for interactive login or arbitrary commands:

```
command="/opt/claude-home-server/run.sh",no-pty,no-port-forwarding,
no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA...
```

`run.sh` activates the project virtualenv and starts the `claude-home-server`
console script. FastMCP's default transport mode (`server.run()` with no
arguments) reads JSON-RPC from stdin and writes to stdout for the lifetime of
the SSH session.

---

## Server bootstrap sequence

`src/server.py::create_server()` is the single factory function responsible for
wiring everything together:

1. `load_config()` — reads and validates `config/server.yaml` with Pydantic.
2. `load_permissions()` — reads `config/permissions.yaml` (root-owned, 640).
3. Shared cross-cutting services are instantiated:
   - `PermissionEngine(overrides)` — risk-level registry with user overrides.
   - `AuditLogger(config.security.audit_log)` — append-only structured log.
4. Modules are instantiated and their sub-servers mounted onto the root
   `FastMCP("claude-home-server")` instance.
5. `server.run()` starts the stdio event loop.

---

## Module system

### BaseModule

All six modules inherit from `src/modules/base.py::BaseModule`. The base class
provides:

- A dedicated `FastMCP(MODULE_NAME)` sub-server instance per module.
- `_register_tool(name, func, description)` — wraps the raw implementation with
  cross-cutting concerns (see below) and registers it on the sub-server.
- `_wrap_tool(tool_name, func)` — the wrapper that applies, in order:
  1. Circuit breaker check (`CircuitBreaker.check_circuit`).
  2. Burst limit check (`CircuitBreaker.check_burst_limit`).
  3. Tool execution.
  4. Output filtering (`OutputFilter.filter_text` / `filter_dict`).
  5. Success recording and audit log write.

On `CircuitBreakerOpen` or `BurstLimitExceeded` the call returns `[BLOCKED] ...`
to Claude. On any other exception the failure is recorded and `[ERROR] ...` is
returned. The wrapper always returns a `str`.

Subclasses implement `_register_tools()` and call `_register_tool` for each
tool they expose. `create_server()` calls `_register_tools()` once and returns
the configured `FastMCP` sub-server for mounting.

### FastMCP sub-server mounting

Each module creates its own `FastMCP` instance, registers tools on it, and
returns it. The root server calls `mcp.mount(module.create_server())`. This
keeps every module's tool namespace isolated and allows conditional mounting
(Home Assistant and Plex modules are skipped when `enabled: false` in config).

---

## Module reference

### Discovery module — 2 tools

| Tool | Risk | Description |
|------|------|-------------|
| `discover` | read | Multi-scope server survey: system, services, ports, storage, network, docker, crontabs, all. |
| `health_check` | read | MCP server self-diagnosis: config load, service reachability, backup dir and audit log writability. |

### System module — 12 tools

| Tool | Risk | Description |
|------|------|-------------|
| `system_query` | read | Multi-scope OS info: info, processes, services, updates, firewall. |
| `system_logs` | read | journalctl log tail for any systemd unit. |
| `system_auth_logs` | read | Authentication and login events from auth.log or sshd. |
| `system_sessions` | read | Active login sessions via loginctl and w. |
| `system_disk_health` | read | SMART drive health via smartctl, with df fallback. |
| `system_failed_services` | read | List of systemd units in failed state. |
| `system_service_restart` | moderate | Restart a named systemd service. |
| `system_service_toggle` | elevated | Enable or disable a service's autostart. |
| `system_update_apply` | critical | Apply pending apt upgrades. |
| `system_package_install` | critical | Install a single apt package. |
| `system_firewall_edit` | critical | Add or delete a UFW firewall rule. |
| `system_reboot` | critical | Reboot the server. |

### Docker module — 12 tools

| Tool | Risk | Description |
|------|------|-------------|
| `docker_info` | read | Container, image, network, or volume inspection. |
| `docker_logs` | read | Tail container logs. |
| `docker_compose_validate` | read | Parse and security-check a compose file without applying it. |
| `docker_start` | moderate | Start a stopped container. |
| `docker_stop` | moderate | Stop a running container. |
| `docker_restart` | moderate | Restart a container. |
| `docker_compose_edit` | critical | Write a new docker-compose.yaml (validated by ComposeValidator before write). |
| `docker_compose_up` | critical | Run `docker compose up -d`. |
| `docker_compose_down` | critical | Run `docker compose down`. |
| `docker_compose_pull` | critical | Pull updated images for a compose project. |
| `docker_prune` | critical | Remove unused images, volumes, networks, or all. |
| `docker_remove` | critical | Remove a container. |

### Filesystem module — 7 tools

| Tool | Risk | Description |
|------|------|-------------|
| `fs_read` | read | Read a file (PathValidator enforced). |
| `fs_list` | read | List directory contents. |
| `fs_search` | read | Glob search within allowed paths. |
| `fs_diff` | read | Show diff between a file and its most recent backup. |
| `fs_backup_list` | read | List existing backup files. |
| `fs_write` | critical | Write file content (PathValidator + backup created first). |
| `fs_backup_restore` | critical | Restore a file from a named backup. |

### Home Assistant module — 13 tools

| Tool | Risk | Description |
|------|------|-------------|
| `ha_query` | read | Query HA status, entities, entity state, or history. |
| `ha_config_query` | read | List or inspect automations, scenes, or scripts. |
| `ha_logs` | read | Retrieve recent HA error log lines. |
| `ha_check_config` | read | Trigger HA's built-in config-check endpoint. |
| `ha_toggle_entity` | moderate | Toggle a HA entity on/off. |
| `ha_call_service` | moderate | Call any HA service with arbitrary data. |
| `ha_trigger_automation` | moderate | Manually trigger an automation by ID. |
| `ha_activate_scene` | moderate | Activate a scene by ID. |
| `ha_create_automation` | elevated | Create a new automation from YAML (HAConfigValidator applied). |
| `ha_edit_automation` | elevated | Update an existing automation from YAML. |
| `ha_delete_automation` | elevated | Permanently delete an automation. |
| `ha_restart` | elevated | Restart the Home Assistant process. |
| `ha_edit_config` | critical | Edit a raw HA config file (PathValidator + backup before write). |

### Plex module — 9 tools

| Tool | Risk | Description |
|------|------|-------------|
| `plex_status` | read | Media server status and version. |
| `plex_libraries` | read | List all Plex libraries. |
| `plex_sessions` | read | Active playback sessions. |
| `plex_users` | read | Managed and home users list. |
| `plex_scan_library` | moderate | Trigger a library scan by library ID. |
| `plex_optimize` | moderate | Run database optimization for a library. |
| `plex_empty_trash` | moderate | Empty trash for a library. |
| `plex_manage_user` | elevated | Modify a user's permissions. |
| `plex_settings` | elevated | Set a Plex server preference key/value. |

**Total: 55 tools across 6 modules.**

---

## Safety layer

The safety layer lives in `src/safety/` and is applied unconditionally. No
module bypasses it.

### PathValidator (`src/safety/path_validator.py`)

The filesystem security boundary. All file access must call
`validate_or_raise(path)` before any I/O occurs. The validator resolves paths
with `os.path.realpath()` exactly once (eliminating symlink and `..` tricks) and
checks in priority order:

1. Input sanity: empty string, null bytes, path length > 4096.
2. Hardcoded blocklist (not overridable): `/etc/shadow`, `/etc/sudoers`,
   `/etc/sudoers.d`, `/root`, `/proc`, `/sys`, `/dev`.
3. Hardcoded filename patterns: `*.pem`, `*.key`, `*id_rsa*`, `*id_ed25519*`,
   `*id_ecdsa*`, `*id_dsa*`, `.env`, `*.env`, `.env.*`.
4. Hardcoded path segments: any path containing `.ssh` or `secrets` as a
   component is denied.
5. User-supplied extra blocklist (from `config/server.yaml`).
6. User-supplied allowlist — default-deny: a path not explicitly listed is
   rejected.

Error messages are intentionally generic to avoid leaking filesystem layout
information to callers.

### InputSanitizer (`src/safety/input_sanitizer.py`)

Pydantic v2 models that validate every tool parameter at the MCP boundary.
Each model is named `<ToolName>Input` and enforces:

- Type coercion and field presence.
- Maximum string and content lengths (paths: 4096 chars, content: 1 MB).
- Regex allowlists for structured identifiers (service names, container names,
  HA entity IDs, package names, UFW rules).
- Null-byte rejection on all string fields.
- Glob-only patterns for `fs_search` (regex metacharacters blocked to prevent
  ReDoS).

### OutputFilter (`src/safety/output_filter.py`)

Applied to every tool return value before it reaches Claude. Three filter passes
run unconditionally:

- **Inline text patterns**: redacts `token = ...`, `password: ...`, Bearer
  headers, PEM private key blocks, AWS key patterns.
- **Dict key matching**: any key matching patterns like `.*token.*`, `.*secret.*`,
  `.*password.*`, `.*auth.*`, `.*credential.*`, `.*api.?key.*`, `.*private.*`
  has its value replaced with `***FILTERED***`.
- **env-var list filtering**: `KEY=VALUE` lines where the key is sensitive are
  masked.
- **Size cap**: output is truncated at 50,000 bytes with a `[TRUNCATED]` marker
  to prevent denial-of-service via oversized output.

### ComposeValidator (`src/safety/compose_validator.py`)

Validates a parsed Docker Compose dict before any file is written. Critical
violations block the operation; warnings are surfaced but do not block.

Critical: `privileged: true`, any `cap_add`, `network_mode: host`, `pid: host`,
`ipc: host`, `devices`, `sysctls`, volume mounts to `/`, `/etc`, `/root`,
`/proc`, `/sys`, `/dev`, or `/var/run/docker.sock`.

Warnings: volume mounts outside configured allowed prefixes, `restart: no`, no
`deploy.resources.limits`, `DOCKER_HOST` or `DOCKER_SOCKET` in environment.

### HAConfigValidator (`src/safety/ha_config_validator.py`)

Validates Home Assistant YAML before any write or API call. Applied to
`ha_create_automation`, `ha_edit_automation`, and `ha_edit_config`.

Critical (blocks operation): `shell_command`, `command_line`, `python_script`,
`rest_command` — checked both at the top level and as `platform:` values in
sensor/switch list entries.

Warnings: `custom_components` references, `packages` directive, `panel_iframe`
with non-local URLs, plaintext secrets in key/value pairs (rather than
`!secret` references).

---

## Cross-cutting services

### PermissionEngine (`src/permissions.py`)

Maps every tool name to a `RiskLevel` enum value: `read`, `moderate`,
`elevated`, or `critical`. The mapping is the single source of truth in
`DEFAULT_TOOL_LEVELS`. User-supplied overrides from `config/permissions.yaml`
take precedence. Unknown tools default to `critical`.

Derived decisions:

- `auto_approve`: `True` for `read` and `moderate`. `elevated` and `critical`
  require explicit human confirmation from Claude's operator.
- `requires_backup`: `True` only for `critical`. A `BackupManager.create_backup`
  call is made before any critical tool mutates a file.

### AuditLogger (`src/audit.py`)

An append-only structured log written with structlog's `PrintLogger` to a
private file handle. Each tool invocation (including read-only ones) produces
one JSON-per-line record containing: ISO timestamp (UTC), tool name, risk level,
sanitized parameters (sensitive keys redacted, values truncated at 500 chars),
result status (`success`, `error`, `denied`, `dry_run`), and duration in ms.

The logger falls back to `sys.stderr` when the log directory is not writable so
the server can still start in restricted environments.

Recommended hardening after installation: `sudo chattr +a /var/log/claude-home-server/audit.log`

### CircuitBreaker (`src/utils/circuit_breaker.py`)

Two independent protection mechanisms:

**Per-tool circuit breaker**: After `max_consecutive_failures` (default: 3)
back-to-back errors for a single tool, `check_circuit` raises
`CircuitBreakerOpen`. The circuit stays open until `reset(tool_name)` is called.

**Burst rate limiter**: `critical`-level tools share a sliding-window counter.
After `burst_limit_critical` (default: 5) calls within `burst_window_minutes`
(default: 5 minutes), `check_burst_limit` raises `BurstLimitExceeded`. Only
`CRITICAL`-risk tools are rate-limited; all other risk levels pass through
unconditionally. Both use `time.monotonic()` so wall-clock adjustments do not
affect the window.

---

## subprocess_safe utility (`src/utils/subprocess_safe.py`)

All subprocess execution goes through `safe_run()` or `safe_run_sudo()`. The
invariants are:

- `shell=False` on every call — no shell injection possible.
- Environment is always replaced with `CLEAN_ENV` (fixed `PATH`, `HOME`,
  `LANG`, `LC_ALL`) plus optional extras. No credentials or injected variables
  from the parent process.
- `stdin` is always `subprocess.DEVNULL`.
- Output is capped at 1 MB per stream.
- A hard timeout (default: 30 seconds) is applied; the process is killed on
  expiry.

`safe_run_sudo(wrapper_script, args)` additionally validates that the wrapper
script path starts with `/usr/local/bin/mcp-` before spawning. This restricts
`sudo` escalation to a set of pre-approved scripts installed at deployment time.

---

## Configuration system

Two YAML files are loaded at startup:

- `config/server.yaml` — server identity, service URLs and token file paths,
  filesystem allowlist/blocklist, security thresholds, HTTP timeouts. Validated
  by Pydantic; missing file produces safe defaults.
- `config/permissions.yaml` — tool risk-level overrides. Should be owned by
  `root:mcp-server` with mode `640` so the MCP process can read but not modify
  it. Missing file produces zero overrides (all defaults apply).

See `docs/CONFIGURATION.md` for the full field reference.

---

## Docker Socket Proxy

Docker daemon access goes through a
[Tecnativa docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
container. The proxy sits between the MCP server and the Docker socket and
whitelists only the Docker API endpoints that the MCP modules require. The
`config/server.yaml` `services.docker.socket_proxy` field points to the proxy
URL (default `http://localhost:2375`), not to the raw Unix socket. This means
even if the MCP process is compromised, it cannot reach privileged Docker API
operations that the proxy does not expose.

---

## Backup system (`src/utils/backup.py`)

`BackupManager` creates timestamped backup files in `config/security/backup_dir`
(default `/var/backups/claude-home-server`) before any `critical`-tier write.
Naming convention: `{original_basename}.{YYYYMMDDTHHMMSS}.bak`.

Retention: files older than `backup_retention_days` (default: 30) are removed;
the count per original file is capped at `backup_max_per_file` (default: 50).
`FileLock` prevents concurrent backup races.
