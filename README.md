# claude-home-server

**MCP Server zur Verwaltung privater Ubuntu-Homeserver durch Claude Code.**
**MCP server for managing private Ubuntu home servers through Claude Code.**

---

Claude Code verbindet sich per SSH mit deinem Server und kann ihn vollstaendig verwalten: Docker-Container, Home Assistant, Plex, System-Administration, Dateien — alles ueber strukturierte, abgesicherte Tools mit 4-stufigem Berechtigungssystem.

Claude Code connects via SSH to your server and manages it through structured, secured tools with a 4-tier permission system: Docker containers, Home Assistant, Plex, system administration, files — everything.

```
┌─────────────────┐    SSH (stdio)    ┌──────────────────────────┐
│  Claude Code     │ ───────────────> │  Ubuntu Home Server      │
│  (Mac/PC/Web)    │ <─────────────── │  claude-home-server      │
└─────────────────┘    JSON-RPC       │  (MCP over stdin/stdout) │
                                      └──────────────────────────┘
```

## Inhaltsverzeichnis / Table of Contents

- [Deutsch](#deutsch)
  - [Warum dieses Projekt?](#warum-dieses-projekt)
  - [Architekturentscheidungen](#architekturentscheidungen)
  - [Sicherheitskonzept](#sicherheitskonzept)
  - [Tools im Ueberblick](#tools-im-ueberblick)
  - [Installationsanleitung](#installationsanleitung)
  - [Konfiguration](#konfiguration)
  - [Nutzung](#nutzung)
- [English](#english)
  - [Why this project?](#why-this-project)
  - [Architecture decisions](#architecture-decisions)
  - [Security concept](#security-concept)
  - [Tools overview](#tools-overview)
  - [Installation guide](#installation-guide)
  - [Configuration](#configuration)
  - [Usage](#usage)
- [Development](#development)
- [License](#license)

---

# Deutsch

## Warum dieses Projekt?

Homeserver-Betreiber haben komplexe Stacks (Home Assistant, Docker, Plex, Reverse Proxies, Pi-hole, ...), aber oft nicht die Expertise, sie effizient zu verwalten. Konfigurationsaenderungen erfordern stundenlanges Recherchieren von YAML-Syntax, Docker-Befehlen und Service-spezifischen APIs.

**Claude kann diese Arbeit uebernehmen — braucht aber eine sichere, strukturierte Bruecke zum Server.**

claude-home-server ist diese Bruecke: ein MCP-Server (Model Context Protocol), der auf dem Ubuntu-Server laeuft und Claude Code kontrollierten Zugriff auf alle Dienste gibt.

### Was kann Claude damit tun?

- **Server analysieren**: Hardware, Dienste, Ports, Docker-Container, Cronjobs, Netzwerk
- **Docker verwalten**: Container starten/stoppen, Compose-Dateien bearbeiten und deployen, Images aktualisieren
- **System administrieren**: Services neustarten, Pakete installieren, Firewall konfigurieren, Updates einspielen
- **Dateien bearbeiten**: Konfigurationsdateien lesen, schreiben, durchsuchen, vergleichen — mit automatischen Backups
- **Home Assistant steuern** (Phase 3): Entitaeten schalten, Automationen erstellen, Konfiguration bearbeiten
- **Plex verwalten** (Phase 3): Bibliotheken scannen, Benutzer verwalten, Einstellungen aendern

## Architekturentscheidungen

### Warum SSH statt HTTP?

| | SSH (stdio) | HTTP |
|---|---|---|
| **Authentifizierung** | SSH-Key — bereits vorhanden | Eigene Auth-Schicht noetig |
| **Offene Ports** | Keine zusaetzlichen | Mindestens einer |
| **Angriffsoberflaeche** | Minimal — kein Webserver | CORS, CSRF, Token-Management |
| **Einrichtung** | Ein SSH-Key reicht | TLS-Zertifikate, Reverse Proxy |

SSH ist die natuerlichste Loesung: keine zusaetzlichen Ports, keine eigene Authentifizierung, maximale Sicherheit durch `command=,restrict` in `authorized_keys`.

### Warum FastMCP (Python)?

- **Offizielles MCP SDK** — von Anthropic gepflegt, native stdio-Unterstuetzung
- **Pydantic v2** fuer Input-Validierung — jeder Parameter wird typisiert und validiert
- **Modulares Design** — jeder Service ist ein eigenes Modul, das unabhaengig aktivierbar ist
- **Kein Webframework noetig** — MCP kommuniziert ueber stdin/stdout, kein Flask/FastAPI

### Warum kein direkter Docker-Socket-Zugriff?

Der direkte Zugriff auf `/var/run/docker.sock` ist root-equivalent. Stattdessen nutzen wir den **Docker Socket Proxy** (Tecnativa), der nur explizit erlaubte Operationen durchlaesst:

```yaml
# Erlaubt: Container auflisten, starten, stoppen
CONTAINERS: 1
POST: 1

# Blockiert: Container erstellen, Code ausfuehren, Images bauen
CONTAINERS_CREATE: 0
EXEC: 0
BUILD: 0
```

## Sicherheitskonzept

### 4-stufiges Berechtigungssystem

```
┌──────────┬───────────────┬────────────┬──────────────────────────────────┐
│ Stufe    │ Auto-Approve  │ Backup     │ Beispiele                        │
├──────────┼───────────────┼────────────┼──────────────────────────────────┤
│ READ     │ Ja            │ Nein       │ discover, docker_info, fs_read   │
│ MODERATE │ Ja            │ Nein       │ docker_restart, service_restart  │
│ ELEVATED │ Bestaetigung  │ Nein       │ service_toggle, ha_edit_auto     │
│ CRITICAL │ Bestaetigung  │ Ja         │ fs_write, compose_up, reboot     │
└──────────┴───────────────┴────────────┴──────────────────────────────────┘
```

### Defense in Depth — 7 Sicherheitsebenen

1. **SSH-Isolation**: `command=,restrict` — kein Shell-Zugang, kein Port-Forwarding
2. **OS-Privilege-Separation**: Dedizierter `mcp-server` User, sudo nur ueber Wrapper-Skripte
3. **Input-Validierung**: Pydantic v2 Modelle fuer jeden Parameter, Regex-Validierung, Null-Byte-Ablehnung
4. **Path-Validierung**: Hardcoded Blocklist (/etc/shadow, SSH-Keys, .env), Allowlist, realpath()-Aufloesung
5. **Output-Filterung**: Passwoerter, Tokens, API-Keys werden aus allen Ausgaben entfernt
6. **Compose-Validator**: Blockiert `privileged`, `cap_add`, Host-Netzwerk, Device-Mounts
7. **Circuit Breaker**: Stoppt nach 3 aufeinanderfolgenden Fehlern, Burst-Schutz fuer kritische Ops

### Automatische Backups

Vor **jeder** Schreiboperation (fs_write, compose_edit) wird automatisch ein Backup erstellt:
- Speicherort: `/var/backups/claude-home-server/`
- Format: `{dateiname}.{ISO-Zeitstempel}.bak`
- Aufbewahrung: 30 Tage, max. 50 Backups pro Datei

## Tools im Ueberblick

### Discovery (2 Tools)

| Tool | Beschreibung |
|---|---|
| `discover` | Server-Analyse: System, Services, Ports, Storage, Netzwerk, Docker, Cronjobs |
| `health_check` | Selbstdiagnose: Config, Docker, HA, Plex, Backup-Dir, Audit-Log |

### System (12 Tools)

| Tool | Stufe | Beschreibung |
|---|---|---|
| `system_query` | READ | System-Info, Prozesse, Services, Updates, Firewall |
| `system_logs` | READ | Journalctl-Logs fuer beliebige Quellen |
| `system_auth_logs` | READ | Login-Versuche und Auth-Events |
| `system_sessions` | READ | Aktive SSH/Login-Sessions |
| `system_disk_health` | READ | SMART-Werte und Festplattengesundheit |
| `system_failed_services` | READ | Fehlgeschlagene Systemd-Services |
| `system_service_restart` | MODERATE | Service neustarten |
| `system_service_toggle` | ELEVATED | Service aktivieren/deaktivieren |
| `system_update_apply` | CRITICAL | System-Updates einspielen |
| `system_package_install` | CRITICAL | Paket aus offiziellen Repos installieren |
| `system_firewall_edit` | CRITICAL | UFW-Regel hinzufuegen/entfernen (SSH-Port geschuetzt) |
| `system_reboot` | CRITICAL | Server neustarten |

### Docker (12 Tools)

| Tool | Stufe | Beschreibung |
|---|---|---|
| `docker_info` | READ | Container, Images, Netzwerke, Volumes auflisten/inspizieren |
| `docker_logs` | READ | Container-Logs mit Zeilenlimit |
| `docker_compose_validate` | READ | Sicherheitscheck einer Compose-Datei |
| `docker_start` | MODERATE | Container starten |
| `docker_stop` | MODERATE | Container stoppen |
| `docker_restart` | MODERATE | Container neustarten |
| `docker_compose_edit` | CRITICAL | Compose-Datei bearbeiten (validiert + Backup) |
| `docker_compose_up` | CRITICAL | Compose-Stack deployen (validiert zuerst) |
| `docker_compose_down` | CRITICAL | Compose-Stack stoppen |
| `docker_compose_pull` | CRITICAL | Images aktualisieren |
| `docker_prune` | CRITICAL | Ungenutzte Ressourcen entfernen |
| `docker_remove` | CRITICAL | Container entfernen |

### Filesystem (7 Tools)

| Tool | Stufe | Beschreibung |
|---|---|---|
| `fs_read` | READ | Datei lesen (Allowlist-geprueft) |
| `fs_list` | READ | Verzeichnis-Listing |
| `fs_search` | READ | Glob-basierte Dateisuche |
| `fs_diff` | READ | Datei vs. letztes Backup vergleichen |
| `fs_backup_list` | READ | Alle Backups auflisten |
| `fs_write` | CRITICAL | Datei schreiben (Backup + Allowlist) |
| `fs_backup_restore` | CRITICAL | Backup wiederherstellen |

## Installationsanleitung

### Voraussetzungen

- Ubuntu 22.04+ oder Debian 12+
- Python 3.11+
- SSH-Zugang zum Server
- Docker (optional, fuer Docker-Tools)

### Schritt 1: System-User anlegen

```bash
# Auf dem Ubuntu-Server:
sudo useradd -r -m -d /opt/claude-home-server -s /usr/sbin/nologin mcp-server
```

### Schritt 2: Projekt installieren

```bash
sudo -u mcp-server git clone https://github.com/reyk-zepper/claude-home-server.git /opt/claude-home-server
cd /opt/claude-home-server
sudo -u mcp-server python3 -m venv .venv
sudo -u mcp-server .venv/bin/pip install -e .
```

### Schritt 3: Konfiguration erstellen

```bash
# Konfigurationsdateien kopieren
sudo -u mcp-server cp config/server.yaml config/server.local.yaml
sudo -u mcp-server cp config/permissions.yaml config/permissions.local.yaml

# Server-Konfiguration anpassen
sudo -u mcp-server nano config/server.local.yaml
```

Passe mindestens an:
- `services.docker.enabled: true` und `compose_paths`
- `filesystem.allowed_paths` — Verzeichnisse, auf die Claude zugreifen darf
- Service-URLs und Token-Dateien

### Schritt 4: Secrets anlegen

```bash
# Verzeichnis mit eingeschraenkten Rechten
sudo mkdir -p /opt/claude-home-server/secrets
sudo chown mcp-server:mcp-server /opt/claude-home-server/secrets
sudo chmod 700 /opt/claude-home-server/secrets

# Home Assistant Token (aus HA-Profil kopieren)
echo "dein-ha-long-lived-token" | sudo -u mcp-server tee /opt/claude-home-server/secrets/ha_token > /dev/null
sudo chmod 600 /opt/claude-home-server/secrets/ha_token

# Plex Token
echo "dein-plex-token" | sudo -u mcp-server tee /opt/claude-home-server/secrets/plex_token > /dev/null
sudo chmod 600 /opt/claude-home-server/secrets/plex_token
```

### Schritt 5: Startskript erstellen

```bash
cat << 'SCRIPT' | sudo tee /opt/claude-home-server/run.sh
#!/bin/bash
cd /opt/claude-home-server
exec .venv/bin/claude-home-server
SCRIPT
sudo chmod 755 /opt/claude-home-server/run.sh
```

### Schritt 6: SSH-Key einrichten

```bash
# Auf deinem lokalen Rechner (Mac/PC):
ssh-keygen -t ed25519 -C "claude-home-server" -f ~/.ssh/claude_home_server

# Public Key auf den Server kopieren — mit command-Restriction:
echo "command=\"/opt/claude-home-server/run.sh\",restrict $(cat ~/.ssh/claude_home_server.pub)" | \
  ssh dein-user@server-ip "sudo -u mcp-server tee -a /opt/claude-home-server/.ssh/authorized_keys"
```

### Schritt 7: Sudo-Wrapper einrichten

```bash
# Wrapper-Skripte fuer privilegierte Operationen
sudo cp /opt/claude-home-server/scripts/wrappers/* /usr/local/bin/
sudo chmod 755 /usr/local/bin/mcp-*

# Sudoers-Konfiguration
cat << 'SUDOERS' | sudo tee /etc/sudoers.d/mcp-server
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-service-restart
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-service-toggle
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-apt-upgrade
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-apt-install
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-ufw-edit
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-reboot
SUDOERS
sudo chmod 440 /etc/sudoers.d/mcp-server
```

### Schritt 8: Docker Socket Proxy (optional)

```bash
# docker-compose.yaml fuer den Socket Proxy
cat << 'COMPOSE' | sudo tee /opt/docker-compose/socket-proxy/docker-compose.yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    restart: always
    environment:
      CONTAINERS: 1
      IMAGES: 1
      NETWORKS: 1
      POST: 1
      CONTAINERS_CREATE: 0
      EXEC: 0
      BUILD: 0
      COMMIT: 0
      VOLUMES: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "127.0.0.1:2375:2375"
COMPOSE

cd /opt/docker-compose/socket-proxy && docker compose up -d
```

### Schritt 9: Claude Code konfigurieren

Fuege in deine Claude Code MCP-Konfiguration ein:

```json
{
  "mcpServers": {
    "home-server": {
      "command": "ssh",
      "args": [
        "-i", "~/.ssh/claude_home_server",
        "-o", "StrictHostKeyChecking=accept-new",
        "mcp-server@DEINE-SERVER-IP",
        "/opt/claude-home-server/run.sh"
      ]
    }
  }
}
```

### Schritt 10: Testen

Starte Claude Code und frage:

> "Analysiere meinen Homeserver. Was laeuft dort alles?"

Claude nutzt automatisch das `discover`-Tool und gibt dir einen vollstaendigen Ueberblick.

## Konfiguration

### server.yaml

Die vollstaendig kommentierte Beispielkonfiguration liegt unter `config/server.yaml`. Alle Werte haben sichere Defaults — der Server startet auch ohne Konfigurationsdatei.

### permissions.yaml

Ueberschreibt die Standard-Risikostufen einzelner Tools:

```yaml
overrides:
  # Docker-Restart erfordert jetzt Bestaetigung
  docker_restart: "elevated"

  # Firewall-Aenderungen erzwingen immer ein Backup
  system_firewall_edit: "critical"
```

Die Datei gehoert `root:mcp-server` mit Mode `640` — der MCP-Prozess kann seine eigenen Berechtigungen nicht aendern.

## Nutzung

### Beispiele fuer Claude Code

**Server analysieren:**
> "Was laeuft auf meinem Server? Zeig mir alle Docker-Container und offenen Ports."

**Docker-Container verwalten:**
> "Starte den Home Assistant Container neu."
> "Zeig mir die Logs von dem nginx Container, die letzten 50 Zeilen."

**System administrieren:**
> "Gibt es verfuegbare Updates? Wenn ja, installiere sie."
> "Welche Services sind fehlgeschlagen?"

**Dateien bearbeiten:**
> "Zeig mir die Home Assistant configuration.yaml und fuege eine neue Automation hinzu."
> "Vergleiche die aktuelle docker-compose.yaml mit dem letzten Backup."

**Sicherheits-Check:**
> "Pruefe meine Docker-Compose-Dateien auf Sicherheitsprobleme."
> "Gibt es verdaechtige Login-Versuche in den Auth-Logs?"

---

# English

## Why this project?

Home server owners run complex stacks (Home Assistant, Docker, Plex, reverse proxies, Pi-hole, etc.) but often lack the expertise to manage them efficiently. Configuration changes require hours of research into YAML syntax, Docker commands, and service-specific APIs.

**Claude can do this work — but needs a secure, structured bridge to the server.**

claude-home-server is that bridge: an MCP server (Model Context Protocol) that runs on the Ubuntu server and gives Claude Code controlled access to all services.

### What can Claude do with it?

- **Analyze the server**: Hardware, services, ports, Docker containers, cron jobs, network
- **Manage Docker**: Start/stop containers, edit and deploy compose files, update images
- **Administer the system**: Restart services, install packages, configure the firewall, apply updates
- **Edit files**: Read, write, search, and compare configuration files — with automatic backups
- **Control Home Assistant** (Phase 3): Toggle entities, create automations, edit configuration
- **Manage Plex** (Phase 3): Scan libraries, manage users, change settings

## Architecture decisions

### Why SSH instead of HTTP?

| | SSH (stdio) | HTTP |
|---|---|---|
| **Authentication** | SSH key — already there | Custom auth layer needed |
| **Open ports** | None additional | At least one |
| **Attack surface** | Minimal — no web server | CORS, CSRF, token management |
| **Setup** | One SSH key | TLS certificates, reverse proxy |

SSH is the most natural choice: no additional ports, no custom authentication, maximum security through `command=,restrict` in `authorized_keys`.

### Why FastMCP (Python)?

- **Official MCP SDK** — maintained by Anthropic, native stdio support
- **Pydantic v2** for input validation — every parameter is typed and validated
- **Modular design** — each service is its own module, independently activatable
- **No web framework needed** — MCP communicates over stdin/stdout, no Flask/FastAPI

### Why no direct Docker socket access?

Direct access to `/var/run/docker.sock` is root-equivalent. Instead, we use the **Docker Socket Proxy** (Tecnativa), which only allows explicitly permitted operations:

```yaml
# Allowed: list, inspect, start, stop, restart containers
CONTAINERS: 1
POST: 1

# Blocked: create containers, execute commands, build images
CONTAINERS_CREATE: 0
EXEC: 0
BUILD: 0
```

## Security concept

### 4-tier permission system

```
┌──────────┬───────────────┬────────────┬──────────────────────────────────┐
│ Level    │ Auto-Approve  │ Backup     │ Examples                         │
├──────────┼───────────────┼────────────┼──────────────────────────────────┤
│ READ     │ Yes           │ No         │ discover, docker_info, fs_read   │
│ MODERATE │ Yes           │ No         │ docker_restart, service_restart  │
│ ELEVATED │ Confirmation  │ No         │ service_toggle, ha_edit_auto     │
│ CRITICAL │ Confirmation  │ Yes        │ fs_write, compose_up, reboot     │
└──────────┴───────────────┴────────────┴──────────────────────────────────┘
```

### Defense in depth — 7 security layers

1. **SSH isolation**: `command=,restrict` — no shell access, no port forwarding
2. **OS privilege separation**: Dedicated `mcp-server` user, sudo only through wrapper scripts
3. **Input validation**: Pydantic v2 models for every parameter, regex validation, null byte rejection
4. **Path validation**: Hardcoded blocklist (/etc/shadow, SSH keys, .env), allowlist, realpath() resolution
5. **Output filtering**: Passwords, tokens, API keys are stripped from all outputs
6. **Compose validator**: Blocks `privileged`, `cap_add`, host network, device mounts
7. **Circuit breaker**: Stops after 3 consecutive failures, burst protection for critical ops

### Automatic backups

Before **every** write operation (fs_write, compose_edit), a backup is automatically created:
- Location: `/var/backups/claude-home-server/`
- Format: `{filename}.{ISO-timestamp}.bak`
- Retention: 30 days, max 50 backups per file

## Tools overview

### Discovery (2 tools)

| Tool | Description |
|---|---|
| `discover` | Server survey: system, services, ports, storage, network, Docker, cron jobs |
| `health_check` | Self-diagnosis: config, Docker, HA, Plex, backup dir, audit log |

### System (12 tools)

| Tool | Level | Description |
|---|---|---|
| `system_query` | READ | System info, processes, services, updates, firewall |
| `system_logs` | READ | Journalctl logs for any source |
| `system_auth_logs` | READ | Login attempts and auth events |
| `system_sessions` | READ | Active SSH/login sessions |
| `system_disk_health` | READ | SMART values and disk health |
| `system_failed_services` | READ | Failed systemd services |
| `system_service_restart` | MODERATE | Restart a service |
| `system_service_toggle` | ELEVATED | Enable/disable a service |
| `system_update_apply` | CRITICAL | Apply system updates |
| `system_package_install` | CRITICAL | Install package from official repos |
| `system_firewall_edit` | CRITICAL | Add/remove UFW rule (SSH port protected) |
| `system_reboot` | CRITICAL | Reboot the server |

### Docker (12 tools)

| Tool | Level | Description |
|---|---|---|
| `docker_info` | READ | List/inspect containers, images, networks, volumes |
| `docker_logs` | READ | Container logs with line limit |
| `docker_compose_validate` | READ | Security-check a compose file |
| `docker_start` | MODERATE | Start a container |
| `docker_stop` | MODERATE | Stop a container |
| `docker_restart` | MODERATE | Restart a container |
| `docker_compose_edit` | CRITICAL | Edit compose file (validated + backed up) |
| `docker_compose_up` | CRITICAL | Deploy compose stack (validated first) |
| `docker_compose_down` | CRITICAL | Stop compose stack |
| `docker_compose_pull` | CRITICAL | Pull updated images |
| `docker_prune` | CRITICAL | Remove unused resources |
| `docker_remove` | CRITICAL | Remove a container |

### Filesystem (7 tools)

| Tool | Level | Description |
|---|---|---|
| `fs_read` | READ | Read file (allowlist-checked) |
| `fs_list` | READ | Directory listing |
| `fs_search` | READ | Glob-based file search |
| `fs_diff` | READ | Compare file vs. latest backup |
| `fs_backup_list` | READ | List all backups |
| `fs_write` | CRITICAL | Write file (backup + allowlist) |
| `fs_backup_restore` | CRITICAL | Restore from backup |

## Installation guide

### Prerequisites

- Ubuntu 22.04+ or Debian 12+
- Python 3.11+
- SSH access to the server
- Docker (optional, for Docker tools)

### Step 1: Create system user

```bash
# On the Ubuntu server:
sudo useradd -r -m -d /opt/claude-home-server -s /usr/sbin/nologin mcp-server
```

### Step 2: Install the project

```bash
sudo -u mcp-server git clone https://github.com/reyk-zepper/claude-home-server.git /opt/claude-home-server
cd /opt/claude-home-server
sudo -u mcp-server python3 -m venv .venv
sudo -u mcp-server .venv/bin/pip install -e .
```

### Step 3: Create configuration

```bash
# Copy configuration templates
sudo -u mcp-server cp config/server.yaml config/server.local.yaml
sudo -u mcp-server cp config/permissions.yaml config/permissions.local.yaml

# Edit server configuration
sudo -u mcp-server nano config/server.local.yaml
```

At minimum, configure:
- `services.docker.enabled: true` and `compose_paths`
- `filesystem.allowed_paths` — directories Claude is allowed to access
- Service URLs and token file paths

### Step 4: Set up secrets

```bash
# Create directory with restricted permissions
sudo mkdir -p /opt/claude-home-server/secrets
sudo chown mcp-server:mcp-server /opt/claude-home-server/secrets
sudo chmod 700 /opt/claude-home-server/secrets

# Home Assistant token (copy from HA profile page)
echo "your-ha-long-lived-token" | sudo -u mcp-server tee /opt/claude-home-server/secrets/ha_token > /dev/null
sudo chmod 600 /opt/claude-home-server/secrets/ha_token

# Plex token
echo "your-plex-token" | sudo -u mcp-server tee /opt/claude-home-server/secrets/plex_token > /dev/null
sudo chmod 600 /opt/claude-home-server/secrets/plex_token
```

### Step 5: Create startup script

```bash
cat << 'SCRIPT' | sudo tee /opt/claude-home-server/run.sh
#!/bin/bash
cd /opt/claude-home-server
exec .venv/bin/claude-home-server
SCRIPT
sudo chmod 755 /opt/claude-home-server/run.sh
```

### Step 6: Set up SSH key

```bash
# On your local machine (Mac/PC):
ssh-keygen -t ed25519 -C "claude-home-server" -f ~/.ssh/claude_home_server

# Copy public key to server — with command restriction:
echo "command=\"/opt/claude-home-server/run.sh\",restrict $(cat ~/.ssh/claude_home_server.pub)" | \
  ssh your-user@server-ip "sudo -u mcp-server tee -a /opt/claude-home-server/.ssh/authorized_keys"
```

### Step 7: Set up sudo wrappers

```bash
# Install wrapper scripts for privileged operations
sudo cp /opt/claude-home-server/scripts/wrappers/* /usr/local/bin/
sudo chmod 755 /usr/local/bin/mcp-*

# Configure sudoers
cat << 'SUDOERS' | sudo tee /etc/sudoers.d/mcp-server
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-service-restart
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-service-toggle
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-apt-upgrade
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-apt-install
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-ufw-edit
mcp-server ALL=(ALL) NOPASSWD: /usr/local/bin/mcp-reboot
SUDOERS
sudo chmod 440 /etc/sudoers.d/mcp-server
```

### Step 8: Docker Socket Proxy (optional)

```bash
# docker-compose.yaml for the socket proxy
cat << 'COMPOSE' | sudo tee /opt/docker-compose/socket-proxy/docker-compose.yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    restart: always
    environment:
      CONTAINERS: 1
      IMAGES: 1
      NETWORKS: 1
      POST: 1
      CONTAINERS_CREATE: 0
      EXEC: 0
      BUILD: 0
      COMMIT: 0
      VOLUMES: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "127.0.0.1:2375:2375"
COMPOSE

cd /opt/docker-compose/socket-proxy && docker compose up -d
```

### Step 9: Configure Claude Code

Add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "home-server": {
      "command": "ssh",
      "args": [
        "-i", "~/.ssh/claude_home_server",
        "-o", "StrictHostKeyChecking=accept-new",
        "mcp-server@YOUR-SERVER-IP",
        "/opt/claude-home-server/run.sh"
      ]
    }
  }
}
```

### Step 10: Test it

Start Claude Code and ask:

> "Analyze my home server. What's running on it?"

Claude will automatically use the `discover` tool and give you a complete overview.

## Configuration

### server.yaml

The fully commented example configuration is at `config/server.yaml`. All values have safe defaults — the server starts even without a configuration file.

### permissions.yaml

Override the default risk levels of individual tools:

```yaml
overrides:
  # Docker restart now requires confirmation
  docker_restart: "elevated"

  # Firewall changes always create a backup
  system_firewall_edit: "critical"
```

This file is owned by `root:mcp-server` with mode `640` — the MCP process cannot modify its own permissions.

## Usage

### Example prompts for Claude Code

**Analyze the server:**
> "What's running on my server? Show me all Docker containers and open ports."

**Manage Docker containers:**
> "Restart the Home Assistant container."
> "Show me the logs from the nginx container, last 50 lines."

**System administration:**
> "Are there available updates? If so, install them."
> "Which services have failed?"

**Edit files:**
> "Show me the Home Assistant configuration.yaml and add a new automation."
> "Compare the current docker-compose.yaml with the latest backup."

**Security checks:**
> "Check my Docker Compose files for security issues."
> "Are there suspicious login attempts in the auth logs?"

---

# Development

### Run tests

```bash
python3 -m pytest tests/ -v
```

### Project status

| Phase | Status | Content |
|---|---|---|
| Phase 1: Foundation | Done | Safety layer, permissions, audit, subprocess hardening, discovery |
| Phase 2: Core Modules | Done | System, Docker, Filesystem modules + Compose Validator |
| Phase 3: Service Modules | Planned | Home Assistant, Plex modules |
| Phase 4: Release | Planned | install.sh, setup wizard, documentation, GitHub release |

### Stats

- **33 tools** across 4 modules
- **541 tests** (unit + integration + security)
- **75% code coverage**
- **7 security layers** (SSH, OS separation, input validation, path validation, output filtering, compose validation, circuit breaker)

## License

MIT
