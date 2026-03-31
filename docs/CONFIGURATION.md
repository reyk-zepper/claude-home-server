# Configuration Reference

claude-home-server is configured through two YAML files loaded at startup.
Both files are validated with Pydantic v2; a validation error at startup is
fatal and printed to stderr with field-level detail.

- `config/server.yaml` — primary configuration: service connections, filesystem
  access control, security thresholds, HTTP timeouts.
- `config/permissions.yaml` — optional risk-level overrides for individual tools.

All fields in `server.yaml` are optional. A missing file or an empty file
produces safe defaults and the server will start in a zero-config state.
Services that require a token file must have `enabled: true` and a valid
`token_file` path before their tools will execute.

---

## config/server.yaml

### `server` section

```yaml
server:
  name: "My Home Server"
  config_version: 1
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | `"Home Server"` | Human-readable name used in log output. |
| `config_version` | integer | `1` | Reserved for future automatic migration support. Do not change. |

---

### `services.homeassistant` section

```yaml
services:
  homeassistant:
    enabled: true
    url: "http://localhost:8123"
    token_file: "/opt/claude-home-server/secrets/ha_token"
    config_path: "/opt/homeassistant/config"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Set to `true` to mount the Home Assistant module. When `false` all HA tools are unavailable. |
| `url` | string | `"http://localhost:8123"` | Base URL of the HA instance. Include port; do not add a trailing path. |
| `token_file` | string | `""` | Absolute path to a file containing the Long-Lived Access Token. Single line, no trailing newline. Create the token at Settings > Profile > Long-Lived Access Tokens. |
| `config_path` | string | `""` | Root directory of the HA configuration (the directory that contains `configuration.yaml`). Used by `ha_edit_config` for path validation. |

---

### `services.plex` section

```yaml
services:
  plex:
    enabled: true
    url: "http://localhost:32400"
    token_file: "/opt/claude-home-server/secrets/plex_token"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Set to `true` to mount the Plex module. |
| `url` | string | `"http://localhost:32400"` | Base URL of the Plex Media Server. |
| `token_file` | string | `""` | Absolute path to a file containing the Plex authentication token. See https://support.plex.tv/articles/204059436 for retrieval instructions. |

---

### `services.docker` section

```yaml
services:
  docker:
    enabled: true
    socket_proxy: "http://localhost:2375"
    compose_paths:
      - "/opt/docker-compose"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Set to `true` to mount the Docker module. |
| `socket_proxy` | string | `"http://localhost:2375"` | URL of the Tecnativa Docker Socket Proxy. Never point this at the raw Docker socket or the Docker daemon's TCP API directly. |
| `compose_paths` | list[string] | `[]` | Directories that contain `docker-compose.yaml` files managed by the server. Used by `docker_compose_*` tools to locate compose files. |

---

### `filesystem` section

```yaml
filesystem:
  allowed_paths:
    - "/opt/homeassistant/config"
    - "/opt/docker-compose"
  blocked_paths:
    - "/etc/nginx/ssl"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_paths` | list[string] | `[]` | Directories (or files) that `fs_read`, `fs_write`, `fs_list`, `fs_search`, and `fs_diff` are permitted to access. PathValidator uses default-deny semantics: any path not covered by this list is rejected. |
| `blocked_paths` | list[string] | `[]` | Additional paths to deny even if they fall under an `allowed_paths` entry. Applied after the hardcoded blocklist. |

The hardcoded blocklist in `src/safety/path_validator.py` is always enforced
regardless of this configuration and cannot be overridden:

- Paths: `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`, `/root`, `/proc`,
  `/sys`, `/dev`.
- Filename patterns: `*.pem`, `*.key`, `*id_rsa*`, `*id_ed25519*`, `*id_ecdsa*`,
  `*id_dsa*`, `.env`, `*.env`, `.env.*`.
- Path segments: any path with `.ssh` or `secrets` as a component.

---

### `security` section

```yaml
security:
  protected_ports:
    - 22
  audit_log: "/var/log/claude-home-server/audit.log"
  backup_dir: "/var/backups/claude-home-server"
  backup_retention_days: 30
  backup_max_per_file: 50
  circuit_breaker:
    max_consecutive_failures: 3
    burst_limit_critical: 5
    burst_window_minutes: 5
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `protected_ports` | list[int] | `[22]` | TCP ports that `system_firewall_edit` must never remove or block. Port 22 is always included even if omitted here. |
| `audit_log` | string | `"/var/log/claude-home-server/audit.log"` | Absolute path to the append-only audit log. The parent directory is created on startup. Recommended: `sudo chattr +a <path>` after first write to enforce append-only at the filesystem level. Falls back to stderr when the directory is not writable. |
| `backup_dir` | string | `"/var/backups/claude-home-server"` | Directory where pre-change backups are stored. Created on first use. |
| `backup_retention_days` | integer | `30` | Backups older than this many days are removed by the retention cleanup. |
| `backup_max_per_file` | integer | `50` | Maximum number of backup files kept per original source file, regardless of age. Oldest files are removed first when the cap is exceeded. |
| `circuit_breaker.max_consecutive_failures` | integer | `3` | Number of consecutive failures before a tool's circuit opens. The circuit stays open until it is reset. |
| `circuit_breaker.burst_limit_critical` | integer | `5` | Maximum number of `critical`-risk tool calls allowed within the burst window. |
| `circuit_breaker.burst_window_minutes` | integer | `5` | Sliding window duration for the burst rate limiter, in minutes. |

---

### `http` section

```yaml
http:
  timeout_seconds: 30
  timeout_long_seconds: 600
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout_seconds` | integer | `30` | Default HTTP client timeout in seconds. Used for Home Assistant and Plex API calls. |
| `timeout_long_seconds` | integer | `600` | Extended timeout for long-running operations such as `docker compose pull` and `system_update_apply`. |

---

## config/permissions.yaml

The permissions file allows overriding the default risk level assigned to
individual tools. It should be owned by `root:mcp-server` with mode `640`
so the MCP process can read the policy but cannot modify it at runtime.

```yaml
overrides:
  docker_restart: "elevated"
  ha_toggle_entity: "read"
  system_firewall_edit: "critical"
```

The `overrides` key is a mapping of tool name to risk level string. Valid levels:

| Level | Auto-approve | Requires backup | Meaning |
|-------|-------------|-----------------|---------|
| `read` | yes | no | Non-mutating. No side effects. |
| `moderate` | yes | no | Mutating but reversible. Auto-approved. |
| `elevated` | no | no | Significant change. Requires explicit human confirmation. |
| `critical` | no | yes | High-impact. Requires confirmation and triggers an automatic backup before execution. |

Any tool not listed in `overrides` uses the built-in default from
`src/permissions.py::DEFAULT_TOOL_LEVELS`. Unknown tool names (not in the
default registry and not in overrides) default to `critical`.

The file is validated at startup. An invalid level string (e.g. a typo) raises
a `ValueError` immediately so misconfigured deployments fail fast.

**Example: tighten all Docker write operations**

```yaml
overrides:
  docker_start: "elevated"
  docker_stop: "elevated"
  docker_restart: "elevated"
  docker_compose_up: "critical"
  docker_compose_down: "critical"
```

**Example: loosen read-only HA tools on a test server**

```yaml
overrides:
  ha_toggle_entity: "read"
  ha_call_service: "read"
```

---

## Environment variables

claude-home-server does not read any environment variables for configuration.
All settings are file-based to avoid secrets appearing in process listings or
being inherited by child processes.

The subprocess execution utility (`src/utils/subprocess_safe.py`) replaces the
environment entirely for all spawned subprocesses with a minimal clean
environment:

```
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/opt/claude-home-server
LANG=C.UTF-8
LC_ALL=C.UTF-8
```

This ensures no credentials or injected variables from the parent SSH session
reach child processes.

---

## Secret management

Tokens for Home Assistant and Plex are stored in separate files, not in
`server.yaml`. This prevents secrets from appearing in config file backups,
version control, or log output.

**Creating a secret file:**

```bash
# Create the secrets directory
sudo mkdir -p /opt/claude-home-server/secrets
sudo chown root:mcp-server /opt/claude-home-server/secrets
sudo chmod 750 /opt/claude-home-server/secrets

# Write the Home Assistant token (no trailing newline)
printf '%s' 'your-long-lived-access-token' | \
  sudo tee /opt/claude-home-server/secrets/ha_token > /dev/null

# Write the Plex token
printf '%s' 'your-plex-token' | \
  sudo tee /opt/claude-home-server/secrets/plex_token > /dev/null

# Restrict permissions
sudo chown root:mcp-server /opt/claude-home-server/secrets/ha_token
sudo chmod 640 /opt/claude-home-server/secrets/ha_token

sudo chown root:mcp-server /opt/claude-home-server/secrets/plex_token
sudo chmod 640 /opt/claude-home-server/secrets/plex_token
```

`load_secret()` in `src/config.py` reads the file at runtime and warns (but
does not block) if the permissions are wider than `0o600`. The token is stripped
of leading/trailing whitespace. An empty file raises `ValueError` at startup.

**Never store tokens in `server.yaml`.** The `token_file` field is a path, not
a value.

---

## Backup configuration

The backup system (`src/utils/backup.py`) creates timestamped copies of files
before any `critical`-tier write operation. Backup files are named:

```
{original_basename}.{YYYYMMDDTHHMMSS}.bak
```

Example: `automations.yaml.20260329T142200.bak`

The backup directory should be on a separate filesystem or at minimum outside
the directories managed by the server. Recommended ownership: `root:mcp-server`,
mode `750`.

Retention is enforced by two rules applied on each cleanup pass:

1. Files older than `backup_retention_days` are deleted.
2. When more than `backup_max_per_file` backups exist for one original file,
   the oldest are removed until the count is within the limit.

Backups are not encrypted. Ensure the backup directory is not accessible to
other users on the system.
