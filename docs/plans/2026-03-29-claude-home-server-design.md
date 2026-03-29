# claude-home-server — Design Document

> MCP Server for managing private Ubuntu home servers through Claude Code.
> Designed for Home Assistant, Docker, Plex, and full system administration.

**Date:** 2026-03-29
**Status:** Approved Design — Ready for Implementation

---

## 1. Problem Statement

Home server owners run complex stacks (Home Assistant, Docker, Plex, reverse proxies, Pi-hole, etc.) but lack the expertise to manage them efficiently. Configuration changes require hours of research into YAML syntax, Docker commands, and service-specific APIs. Claude can do this work — but needs a secure, structured bridge to the server.

## 2. Solution

An MCP (Model Context Protocol) server that runs on the Ubuntu home server. Claude Code connects via SSH and gains structured, permission-controlled access to all services. The server provides two layers:

- **Exploration Layer** — Read-only tools to analyze and understand the server
- **Action Layer** — Write tools to manage services, with tiered permissions

## 3. Architecture

### Transport: stdio over SSH

```
Claude Code (local Mac) → SSH → Ubuntu Server → MCP Server Process (stdio)
```

Claude Code configuration:
```json
{
  "mcpServers": {
    "home-server": {
      "command": "ssh",
      "args": ["mcp-server@192.168.x.x", "/opt/claude-home-server/run.sh"]
    }
  }
}
```

- No HTTP port exposed, no authentication layer needed — SSH handles everything
- MCP process lives only during the conversation
- SSH key with `command=` restriction in `authorized_keys`:
  ```
  command="/opt/claude-home-server/run.sh",restrict ssh-ed25519 AAAA...
  ```
  This ensures: no shell access, no port forwarding, only the MCP server can run.

### Tech Stack

| Purpose | Library | Rationale |
|---|---|---|
| MCP Framework | `mcp` (FastMCP) | Official Python MCP SDK, native stdio support |
| Validation | `pydantic` v2 | Input/config validation, JSON Schema generation |
| Docker | `docker` SDK | Official, accessed via socket proxy only |
| HTTP Client | `httpx` | Async-capable, used for HA + Plex APIs directly |
| YAML | `pyyaml` + `safe_load()` | Config parsing, never unsafe load |
| Process Mgmt | `subprocess` (stdlib) | No shell=True, argument lists only |
| Logging | `structlog` | Structured audit logging |
| File Locking | `filelock` | Prevent concurrent config edits |
| Testing | `pytest` + `pytest-asyncio` + `hypothesis` | Property-based testing for validators |

**Deliberately no dependencies for:** Web framework (no HTTP server), database (filesystem-based state), auth (SSH handles it), Plex library (httpx directly).

## 4. Security Architecture

### 4.1 OS-Level Privilege Separation

The MCP server runs as a dedicated `mcp-server` system user with minimal privileges. Security is enforced at the OS level, not just in Python code.

**Sudoers:** No wildcards. Wrapper scripts that only accept preconfigured service names:
```bash
# /usr/local/bin/mcp-restart-service
ALLOWED=$(cat /opt/claude-home-server/config/allowed-services.list)
if echo "$ALLOWED" | grep -qw "$1"; then
    systemctl restart "$1"
else
    echo "Service $1 not allowed" >&2; exit 1
fi
```
```
# /etc/sudoers.d/mcp-server
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-restart-service
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-service-status
# ... only wrapper scripts, never direct commands
```

**Docker Socket Proxy** (Tecnativa): No direct Docker socket access.
```yaml
# Allowed (read + basic management)
CONTAINERS: 1   # list, inspect, start, stop, restart
IMAGES: 1        # list only
NETWORKS: 1      # list only
POST: 1          # for start/stop/restart only

# Blocked (dangerous operations)
CONTAINERS_CREATE: 0
EXEC: 0
BUILD: 0
COMMIT: 0
VOLUMES: 0       # no volume mount manipulation
```

**AppArmor:** Optional reference profile shipped in v1, mandatory in v2.

### 4.2 Permission System — 4 Risk Levels

```yaml
levels:
  read:        # No risk — auto-approve
    auto: true
    examples: [discover, docker_info, ha_query, system_query, fs_read]

  moderate:    # Reversible actions — auto-approve
    auto: true
    examples: [docker_restart, ha_toggle_entity, plex_scan_library]

  elevated:    # Config-adjacent changes — requires confirmation
    auto: false
    examples: [ha_create_automation, ha_edit_automation, system_service_toggle]

  critical:    # Destructive or security-relevant — requires confirmation + backup
    auto: false
    requires_backup: true
    examples: [docker_compose_edit, docker_compose_up, fs_write,
               ha_edit_config, system_update_apply, system_firewall_edit,
               system_reboot, docker_remove, docker_prune]
```

User overrides in `permissions.yaml` (root:mcp-server 640 — MCP process cannot modify its own permissions):
```yaml
overrides:
  docker_restart: "elevated"    # stricter than default
  ha_toggle_entity: "read"      # more permissive
```

### 4.3 Safety Mechanisms

**Automatic Backups:**
- Trigger: Every `fs_write`, `ha_edit_config`, `docker_compose_edit`
- Location: `/var/backups/claude-home-server/`
- Naming: `{filename}.{ISO-timestamp}.bak`
- Retention: 30 days, max 50 backups per file
- Cleanup: Oldest beyond retention auto-deleted

**Circuit Breaker:**
- After 3 consecutive failures → stop and inform user
- Burst protection: Max 5 critical calls per 5 minutes
- Configurable thresholds in `server.yaml`

**Dry-Run Mode:**
- All critical tools accept `dry_run: bool` parameter
- `dry_run=true` returns what WOULD happen without executing
- Claude Code's native permission system handles user confirmation

**Subprocess Hardening** (`subprocess_safe.py`):
```python
def safe_run(args: list[str], timeout: int = 30, max_output: int = 1_000_000) -> Result:
    result = subprocess.run(
        args,
        shell=False,
        env=CLEAN_ENV,                  # No inherited PATH/LD_PRELOAD
        cwd="/opt/claude-home-server",  # Explicit
        timeout=timeout,                # Always set
        stdin=subprocess.DEVNULL,       # No input
        capture_output=True,
    )
    # Truncate output if > max_output bytes
    return Result(stdout=result.stdout[:max_output], ...)
```

### 4.4 Filesystem Security

**Path Validation** (enforced on every file access):
```python
def is_path_allowed(path: str, allowlist: list, blocklist: list) -> bool:
    real = os.path.realpath(path)  # Resolve symlinks
    for b in HARDCODED_BLOCKLIST + blocklist:  # Hardcoded first
        if real.startswith(os.path.realpath(b)):
            return False
    for a in allowlist:
        if real.startswith(os.path.realpath(a)):
            return True
    return False  # Default deny
```

**Hardcoded Blocklist** (not overridable via config):
```
/etc/shadow, /etc/sudoers, /etc/sudoers.d/
/root/, /home/*/.ssh/
/proc/*/environ, /proc/kcore, /sys/
**/*.pem, **/*.key, **/*id_rsa*, **/*id_ed25519*
**/.env, **/*secret*, **/*password*
/opt/claude-home-server/secrets/
```

### 4.5 Validators

**Compose-File Validator** — blocks before `docker_compose_up`:
- `privileged: true`
- `cap_add` (any)
- `network_mode: host`
- `pid: host`, `ipc: host`
- `devices` (direct device access)
- `sysctls` (kernel parameters)
- Volume mounts outside allowed paths
- Unrecognized images (optional whitelist)

**HA-Config Validator** — blocks before `ha_edit_config` / `ha_restart`:
- `shell_command:`
- `command_line:`
- `python_script:`
- `rest_command:` (SSRF risk)
- Custom component paths

### 4.6 Output Filtering

All tool outputs are filtered before returning to Claude:
- Environment variables matching `*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*KEY*`, `*CREDENTIAL*` → masked as `***`
- Docker inspect: labels, args, and command filtered for sensitive patterns
- `.env` files excluded from all discovery
- Output size limited per tool call (configurable, default 50KB)

### 4.7 Audit Log

- Append-only file (`chattr +a` on ext4/xfs)
- Location: `/var/log/claude-home-server/audit.log`
- Schema: `{timestamp, tool, risk_level, parameters, result_status, duration_ms}`
- Structured JSON via `structlog`
- Log rotation handled with temporary `chattr -a`, rotate, `chattr +a`

## 5. Tool Catalog

### Consolidated Read Tools (~15 tools)

| Tool | Description |
|---|---|
| `discover(scope)` | System, services, ports, storage, network, docker, crontabs, or all |
| `health_check` | MCP server self-diagnosis: permissions, service reachability |
| `system_query(scope)` | Info, processes, services, updates, firewall |
| `system_logs(source, lines)` | Journalctl / logfiles with line limit |
| `system_auth_logs(lines)` | Auth log for login monitoring |
| `system_sessions` | Active SSH/login sessions |
| `system_disk_health` | SMART values, disk predictions |
| `system_failed_services` | Proactively find broken services |
| `docker_info(resource)` | Containers, images, networks, volumes (env filtered) |
| `docker_logs(container, lines)` | Container logs with line limit |
| `docker_compose_validate(path)` | Security-check a compose file before deploy |
| `ha_query(scope)` | Status, entities, entity detail, entity history |
| `ha_config_query(type)` | Automations, scenes, scripts (with detail by ID) |
| `ha_logs(lines)` | Home Assistant logs |
| `ha_check_config` | Validate HA config without restart |
| `plex_status` | Server status, version, active streams |
| `plex_libraries` | All libraries with stats |
| `plex_sessions` | Active playback sessions |
| `plex_users` | Managed users and access |
| `fs_read(path)` | Read file (allowlist + symlink resolution) |
| `fs_list(path)` | Directory listing |
| `fs_search(path, pattern)` | Find files by glob pattern (no regex — no ReDoS) |
| `fs_diff(path)` | Compare current file vs. latest backup |
| `fs_backup_list` | List all backups |

### Moderate Tools (auto-approve)

| Tool | Description |
|---|---|
| `system_service_restart(name)` | Restart a systemd service (via wrapper script) |
| `docker_start(container)` | Start container |
| `docker_stop(container)` | Stop container (warns if same compose project) |
| `docker_restart(container)` | Restart container |
| `ha_toggle_entity(id)` | Toggle entity on/off |
| `ha_call_service(domain, service, data)` | Call HA service |
| `ha_trigger_automation(id)` | Manually trigger automation |
| `ha_activate_scene(id)` | Activate scene |
| `plex_scan_library(id)` | Trigger library scan |
| `plex_optimize(id)` | Start media optimization |
| `plex_empty_trash(id)` | Empty library trash |

### Elevated Tools (requires confirmation)

| Tool | Description |
|---|---|
| `system_service_toggle(name, enabled)` | Enable/disable systemd service |
| `ha_create_automation(yaml)` | Create new automation (via API) |
| `ha_edit_automation(id, yaml)` | Edit automation (via API) |
| `ha_delete_automation(id)` | Delete automation |
| `ha_restart` | Restart Home Assistant |
| `plex_manage_user(id, permissions)` | Change user permissions |
| `plex_settings(key, value)` | Change Plex settings |

### Critical Tools (requires confirmation + backup)

| Tool | Description |
|---|---|
| `docker_compose_edit(path, content)` | Edit compose file (validated + backed up) |
| `docker_compose_up(path)` | Deploy compose stack (validated first) |
| `docker_compose_down(path)` | Stop compose stack |
| `docker_compose_pull(path)` | Pull updated images (timeout: 600s) |
| `docker_prune(type)` | Remove unused images/volumes/networks |
| `docker_remove(container)` | Remove container |
| `fs_write(path, content)` | Write file (allowlist + backup) |
| `fs_backup_restore(backup_path)` | Restore from backup |
| `ha_edit_config(path, content)` | Edit configuration.yaml (validated + backed up) |
| `system_update_apply` | Apply system updates (timeout: 600s) |
| `system_package_install(name)` | Install package (official repos only) |
| `system_firewall_edit(rule)` | Add/remove UFW rule (SSH port protected) |
| `system_reboot` | Reboot server |

All critical tools support `dry_run: bool` parameter.

**Total: ~35 tools** (down from ~60 through read-tool consolidation).

## 6. Configuration

### server.yaml

```yaml
server:
  name: "My Home Server"
  config_version: 1  # For future migrations

services:
  homeassistant:
    enabled: true
    url: "http://localhost:8123"
    token_file: "/opt/claude-home-server/secrets/ha_token"
    config_path: "/opt/homeassistant/config"
  plex:
    enabled: true
    url: "http://localhost:32400"
    token_file: "/opt/claude-home-server/secrets/plex_token"
  docker:
    enabled: true
    socket_proxy: "http://localhost:2375"
    compose_paths:
      - "/opt/docker-compose"

filesystem:
  allowed_paths:
    - "/opt/homeassistant/config"
    - "/opt/docker-compose"
  blocked_paths:    # Additional to hardcoded blocklist
    - "/etc/nginx/ssl"

security:
  protected_ports: [22]
  audit_log: "/var/log/claude-home-server/audit.log"
  backup_dir: "/var/backups/claude-home-server"
  backup_retention_days: 30
  backup_max_per_file: 50
  circuit_breaker:
    max_consecutive_failures: 3
    burst_limit_critical: 5
    burst_window_minutes: 5

http:
  timeout_seconds: 30       # For HA/Plex API calls
  timeout_long_seconds: 600  # For docker pull, system update
```

### permissions.yaml (root:mcp-server 640)

```yaml
overrides: {}
  # docker_restart: "elevated"
  # ha_toggle_entity: "read"
```

### secrets/ (chmod 600, owned by mcp-server)

Token files containing raw token strings. Never exposed in tool outputs, excluded from discovery.

## 7. Installation

### Verified Installation (recommended)

```bash
wget https://github.com/<org>/claude-home-server/releases/latest/download/install.sh
wget https://github.com/<org>/claude-home-server/releases/latest/download/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh
```

### Quick Installation (convenience)

```bash
curl -fsSL https://raw.githubusercontent.com/<org>/claude-home-server/main/install.sh | sudo bash
```

### What install.sh does

1. **Idempotency check** — detects existing installation, supports `--upgrade`, `--repair`, `--uninstall`
2. **System user** — creates `mcp-server` via `useradd --system` (UID < 1000, shell `/bin/sh`)
3. **SSH key setup** — asks for user's public key, installs with `command=,restrict` in authorized_keys
4. **Sudoers** — installs wrapper scripts + sudoers.d file (validated with `visudo -cf`)
5. **Docker Socket Proxy** — deploys Tecnativa container with minimal permissions
6. **Python environment** — venv with pinned dependencies (`pip install --require-hashes`)
7. **Directory structure** — config/, secrets/, backups/ with correct ownership/permissions
8. **Audit log** — creates log file, sets `chattr +a` (append-only)
9. **systemd service** — optional, for auto-start after reboot (`After=docker.service`)
10. **AppArmor** — installs reference profile (optional, not enforced in v1)
11. → **Launches setup wizard**

### Setup Wizard

Interactive, auto-detects running services:

```
═══════════════════════════════════════════════
  claude-home-server Setup Wizard
═══════════════════════════════════════════════

Scanning localhost for known services...

✓ Docker found (24 containers)
✓ Home Assistant found (port 8123)
✓ Plex Media Server found (port 32400)
✓ Nginx found (port 443)
? Pi-hole detected (port 53) — not yet supported, skipping

── Home Assistant ──────────────────────────────
Create a Long-Lived Access Token:
→ http://your-server:8123/profile → Long-Lived Access Tokens

Token: [silent input]
✓ Connected (HA 2024.12.1)

── Plex ────────────────────────────────────────
Enter your Plex token:
→ https://support.plex.tv/articles/204059436

Token: [silent input]
✓ Connected (Plex 1.41.0)

── Docker Socket Proxy ─────────────────────────
Deploying with minimal permissions...
✓ Proxy running (read + start/stop/restart only)

── Security ────────────────────────────────────
SSH port to protect: [22]
Audit logging: [enabled]
Backup directory: [/var/backups/claude-home-server]

── Claude Code Config ──────────────────────────
Add to your Claude Code MCP settings (~/.claude/settings.json):

{
  "mcpServers": {
    "home-server": {
      "command": "ssh",
      "args": ["mcp-server@192.168.1.100",
               "/opt/claude-home-server/run.sh"]
    }
  }
}

✓ Setup complete. Run `mcp-server health` to verify.
```

## 8. Project Structure

```
claude-home-server/
├── src/
│   ├── server.py                  # MCP entry point — registers all modules
│   ├── config.py                  # Config loading + Pydantic validation
│   ├── permissions.py             # Risk level engine
│   ├── audit.py                   # Append-only structured audit logger
│   ├── async_ops.py               # Long-running operations (sync w/ high timeouts)
│   │
│   ├── modules/
│   │   ├── base.py                # Base class for modules
│   │   ├── discovery.py           # discover(scope) + health_check
│   │   ├── system.py              # system_query, system_logs, actions
│   │   ├── docker.py              # docker_info, docker_logs, actions
│   │   ├── homeassistant.py       # ha_query, ha_config_query, actions
│   │   ├── plex.py                # Plex tools (httpx direct, no plexapi)
│   │   └── filesystem.py          # fs_read, fs_write, fs_search, backups
│   │
│   ├── safety/
│   │   ├── path_validator.py      # Allowlist/blocklist + realpath + hardcoded denies
│   │   ├── compose_validator.py   # Docker Compose security checks
│   │   ├── ha_config_validator.py # HA YAML security checks
│   │   ├── input_sanitizer.py     # Pydantic models for all tool inputs
│   │   └── output_filter.py       # Sensitive data masking
│   │
│   └── utils/
│       ├── subprocess_safe.py     # Hardened subprocess (env, cwd, timeout, stdin, output limit)
│       ├── backup.py              # Pre-change backup + restore + retention
│       └── circuit_breaker.py     # Failure tracking + burst protection
│
├── config/
│   ├── server.yaml
│   └── permissions.yaml           # root:mcp-server 640
│
├── secrets/                       # chmod 600, owned by mcp-server
│
├── system/
│   ├── install.sh                 # Idempotent: --upgrade / --repair / --uninstall
│   ├── setup-wizard.sh            # Interactive post-install setup
│   ├── sudoers/
│   │   ├── mcp-server             # /etc/sudoers.d/ file
│   │   └── wrapper-scripts/       # mcp-restart-service, mcp-ufw-edit, etc.
│   ├── apparmor/
│   │   └── mcp-server-profile     # Reference AppArmor profile (optional v1)
│   └── docker-socket-proxy/
│       └── docker-compose.yaml    # Tecnativa proxy configuration
│
├── tests/
│   ├── unit/
│   │   ├── test_path_validator.py       # Path traversal, symlinks, unicode
│   │   ├── test_compose_validator.py    # privileged, cap_add, host mounts, etc.
│   │   ├── test_ha_config_validator.py  # shell_command, python_script, rest_command
│   │   ├── test_input_sanitizer.py      # Injection, overlength, special chars
│   │   ├── test_output_filter.py        # Secret masking
│   │   └── test_permissions.py          # Level assignment, overrides
│   ├── integration/
│   │   ├── test_docker_module.py        # Real proxy + test containers
│   │   ├── test_ha_module.py            # Real HA instance
│   │   ├── test_filesystem_module.py    # Real file ops + backup/restore
│   │   └── test_failure_modes.py        # Proxy down, disk full, service offline
│   ├── security/
│   │   ├── test_path_traversal.py       # All known bypass techniques
│   │   ├── test_escalation_paths.py     # Chained tool attacks
│   │   ├── test_injection.py            # Shell, YAML, command injection
│   │   └── test_mcp_boundary.py         # Malformed tool calls, bad types
│   └── conftest.py                      # hypothesis profiles, fixtures
│
├── docs/
│   ├── THREAT_MODEL.md
│   ├── ARCHITECTURE.md
│   └── CONFIGURATION.md
│
├── SECURITY.md                    # Vulnerability disclosure process
├── README.md
├── LICENSE                        # MIT
├── pyproject.toml
└── requirements.txt               # Pinned with hashes
```

## 9. Implementation Plan

| Phase | Duration | Content |
|---|---|---|
| **1 — Foundation** | 3 weeks | MCP skeleton, config system (Pydantic), permission engine, safety layer (path_validator, input_sanitizer, output_filter), audit logger, circuit breaker, `discover(scope)` + `health_check`. **Security tests for all validators written alongside.** |
| **2 — Core Modules** | 2 weeks | System module, Docker module (via proxy), Filesystem module (with backup), compose_validator, file locking. **Failure-mode integration tests.** |
| **3 — Service Modules** | 2 weeks | Home Assistant module (API + config), Plex module (httpx direct), ha_config_validator, dry_run mode. **Escalation-path security tests.** |
| **4 — Release** | 2 weeks | install.sh (idempotent), setup wizard, sudoers wrapper scripts, Docker Socket Proxy config, documentation (README, THREAT_MODEL, SECURITY, ARCHITECTURE, CONFIGURATION), GitHub release with signed checksums. |

## 10. Open Source

- **License:** MIT
- **Supported Platforms:** Ubuntu 22.04+, Debian 12+ (others: community support)
- **Zero Telemetry:** No phone-home, no analytics, no crash reports
- **SECURITY.md:** Responsible disclosure process with contact email
- **THREAT_MODEL.md:** Documented attacker model, assets, attack surfaces, mitigations

## 11. Future (v2)

- Alerting system (webhooks for security events)
- Mandatory AppArmor enforcement
- Automatic secrets rotation + expiry warnings
- Runtime integrity checking
- Target-context-aware risk levels (per-container/per-service overrides)
- Multi-distro support (Fedora/Arch community contributions)
- Plugin system for community-contributed service modules
