import os
import sys
import json
import logging
import tempfile
import datetime
import calendar
import base64
import urllib.request
import urllib.parse
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from filelock import FileLock, Timeout
from gunicorn.app.base import BaseApplication
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from zoneinfo import ZoneInfo

# optional docker import (best-effort)
try:
    import docker
except Exception:
    docker = None

# Application
app = Flask(__name__)
app.secret_key = os.environ.get("PRUNEMATE_SECRET", "prunemate-secret-key")

# Paths and defaults
CONFIG_PATH = Path(os.environ.get("PRUNEMATE_CONFIG", "/config/config.json"))
# File lock to serialize prune jobs across processes
LOCK_FILE = Path(os.environ.get("PRUNEMATE_LOCK", "/config/prunemate.lock"))
# File to persist the last run key so multiple workers don't double-trigger
LAST_RUN_FILE = Path(os.environ.get("PRUNEMATE_LAST_RUN", "/config/last_run_key"))
LAST_RUN_LOCK = Path(str(LAST_RUN_FILE) + ".lock")
# File to persist all-time statistics
STATS_FILE = Path(os.environ.get("PRUNEMATE_STATS", "/config/stats.json"))

DEFAULT_CONFIG = {
    "schedule_enabled": True,
    "frequency": "daily",
    "time": "03:00",
    "day_of_week": "mon",
    "day_of_month": 1,
    "prune_containers": False,
    "prune_images": True,
    "prune_networks": False,
    "prune_volumes": False,
    "prune_build_cache": False,
    "docker_hosts": [],
    "notifications": {
        "provider": "gotify",
        "gotify": {"enabled": False, "url": "", "token": ""},
        "ntfy": {"enabled": False, "url": "", "topic": "", "token": ""},
        "discord": {"enabled": False, "webhook_url": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        # NEW: Pushover
        "pushover": {"enabled": False, "token": "", "user_key": ""},
        "priority": "medium",
        "only_on_changes": True,
    },
}

config = json.loads(json.dumps(DEFAULT_CONFIG))

# Lock to ensure thread-safe config read/write across workers
import threading
config_lock = threading.RLock()

# In-memory cache (best-effort) for last run; authoritative value is on disk
last_run_key = {"value": None}

# ---- Early exit for CLI tools before initializing heavy components ----
if len(sys.argv) > 1 and sys.argv[1] == "--gen-hash":
    if len(sys.argv) > 2:
        password = sys.argv[2]
        # Generate hash
        raw_hash = generate_password_hash(password)
        safe_hash = base64.b64encode(raw_hash.encode("utf-8")).decode("utf-8")
        print(safe_hash)
        sys.exit(0)
    else:
        print("Usage: python prunemate.py --gen-hash <password>")
        sys.exit(1)


def configure_logging():
    """Configure logging with console and rotating file handlers."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    try:
        Path("/var/log").mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler("/var/log/prunemate.log", maxBytes=5_000_000, backupCount=3)
        # Note: %(asctime)s uses system local time, not app_timezone
        # Custom log() function handles timezone-aware timestamps
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
    except Exception:
        logger.exception("Failed to configure file logging; continuing with console only.")


configure_logging()

# Timezone
tz_name = os.environ.get("PRUNEMATE_TZ", "UTC")
try:
    app_timezone = ZoneInfo(tz_name)
except Exception:
    logging.warning("Invalid timezone '%s', falling back to UTC", tz_name)
    app_timezone = ZoneInfo("UTC")

logging.info("Using timezone: %s", app_timezone)

# Time format (12h or 24h)
use_24h_format = os.environ.get("PRUNEMATE_TIME_24H", "true").lower() in ("true", "1", "yes")
logging.info("Using time format: %s", "24-hour" if use_24h_format else "12-hour")

# Suppress verbose APScheduler job execution logs
logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)

# Scheduler
# Background scheduler for minute heartbeat. Jobs are added in __main__.
scheduler = BackgroundScheduler(
    timezone=app_timezone,
    job_defaults={
        "coalesce": False,
        "misfire_grace_time": 300,
    },
)
scheduler.start()


def log(message: str):
    """Log a message with a timezone-aware timestamp."""
    now = datetime.datetime.now(app_timezone)
    timestamp = now.isoformat(timespec="seconds")
    logging.info("[%s] %s", timestamp, message)


def _redact_for_log(obj):
    """Return a deep-copied structure with secrets redacted for safe logging."""
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            if k.lower() in {"token", "api_key", "apikey", "password", "secret"}:
                redacted[k] = "***"
            elif k.lower() == "url" and isinstance(v, str):
                # Redact username:password in URLs
                parsed = urllib.parse.urlparse(v)
                if parsed.username or parsed.password:
                    clean_url = urllib.parse.urlunparse(
                        (
                            parsed.scheme,
                            f"***:***@{parsed.hostname}"
                            + (f":{parsed.port}" if parsed.port else ""),
                            parsed.path,
                            parsed.params,
                            parsed.query,
                            parsed.fragment,
                        )
                    )
                    redacted[k] = clean_url
                else:
                    redacted[k] = v
            else:
                redacted[k] = _redact_for_log(v)
        return redacted
    if isinstance(obj, list):
        return [_redact_for_log(x) for x in obj]
    return obj


# ---- Cross-process last-run tracking (prevents duplicate scheduled triggers) ----
def _read_last_run_key() -> str | None:
    """Read the last run key from disk in a thread-safe manner."""
    try:
        # Use a short lock to avoid concurrent reads/writes across workers
        with FileLock(str(LAST_RUN_LOCK)):
            if LAST_RUN_FILE.exists():
                return LAST_RUN_FILE.read_text(encoding="utf-8").strip() or None
    except Exception:
        # Best-effort: on any error, fall back to in-memory state
        pass
    return None


def _write_last_run_key(key: str) -> None:
    """Write the last run key to disk atomically."""
    try:
        with FileLock(str(LAST_RUN_LOCK)):
            parent = LAST_RUN_FILE.parent
            parent.mkdir(parents=True, exist_ok=True)
            tmp = LAST_RUN_FILE.with_suffix(LAST_RUN_FILE.suffix + ".tmp")
            tmp.write_text(key, encoding="utf-8")
            try:
                tmp.chmod(0o600)
            except Exception:
                pass
            tmp.replace(LAST_RUN_FILE)
    except Exception:
        # Non-fatal: fall back to in-memory only
        pass


def _clear_last_run_key() -> None:
    """Clear the last run key from memory and disk."""
    last_run_key["value"] = None
    try:
        with FileLock(str(LAST_RUN_LOCK)):
            if LAST_RUN_FILE.exists():
                LAST_RUN_FILE.unlink()
    except Exception:
        pass


# ---- All-time statistics tracking ----
def load_stats() -> dict:
    """Load cumulative statistics from disk with migration support."""
    # Default stats structure (source of truth for all fields)
    default_stats = {
        "total_space_reclaimed": 0,
        "containers_deleted": 0,
        "images_deleted": 0,
        "networks_deleted": 0,
        "volumes_deleted": 0,
        "build_cache_deleted": 0,
        "prune_runs": 0,
        "first_run": None,
        "last_run": None,
    }

    try:
        if STATS_FILE.exists():
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                loaded_stats = json.load(f)
            # Merge with defaults to handle missing fields (forward compatibility)
            merged_stats = json.loads(json.dumps(default_stats))
            for key in default_stats:
                if key in loaded_stats:
                    # Type safety: ensure numeric fields are actually numbers
                    if key in {
                        "total_space_reclaimed",
                        "containers_deleted",
                        "images_deleted",
                        "networks_deleted",
                        "volumes_deleted",
                        "build_cache_deleted",
                        "prune_runs",
                    }:
                        try:
                            merged_stats[key] = int(loaded_stats[key])
                        except (ValueError, TypeError):
                            log(f"Stats field '{key}' has invalid type, using default: 0")
                            merged_stats[key] = 0
                    else:
                        merged_stats[key] = loaded_stats[key]
            return merged_stats
    except json.JSONDecodeError as e:
        log(f"Stats file corrupt (invalid JSON): {e}. Using defaults and will overwrite on next save.")
    except Exception as e:
        log(f"Error loading stats from {STATS_FILE}: {e}")
    return json.loads(json.dumps(default_stats))


def save_stats(stats: dict) -> None:
    """Atomically save statistics to disk."""
    try:
        parent = STATS_FILE.parent
        parent.mkdir(parents=True, exist_ok=True)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, dir=str(parent), encoding="utf-8") as tmp:
                json.dump(stats, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = Path(tmp.name)
            try:
                tmp_path.chmod(0o600)
            except Exception:
                pass
            tmp_path.replace(STATS_FILE)
            log(f"Statistics saved to {STATS_FILE}")
        except Exception:
            if tmp_path and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            raise
    except Exception as e:
        log(f"Error saving statistics: {e}")


def update_stats(containers: int, images: int, networks: int, volumes: int, build_cache: int, space: int) -> None:
    """Update cumulative statistics after a prune run with type safety."""
    stats = load_stats()
    # Type-safe increments (load_stats already validates types, but be defensive)
    try:
        # Extra defensive: convert None to 0 before int() to handle null values from old stats
        stats["containers_deleted"] = int(stats.get("containers_deleted") or 0) + int(containers or 0)
        stats["images_deleted"] = int(stats.get("images_deleted") or 0) + int(images or 0)
        stats["networks_deleted"] = int(stats.get("networks_deleted") or 0) + int(networks or 0)
        stats["volumes_deleted"] = int(stats.get("volumes_deleted") or 0) + int(volumes or 0)
        stats["build_cache_deleted"] = int(stats.get("build_cache_deleted") or 0) + int(build_cache or 0)
        stats["total_space_reclaimed"] = int(stats.get("total_space_reclaimed") or 0) + int(space or 0)
        stats["prune_runs"] = int(stats.get("prune_runs") or 0) + 1
    except (ValueError, TypeError) as e:
        log(f"Type error in stats update: {e}. Stats may be incomplete.")
        # Continue with partial update rather than failing completely

    now = datetime.datetime.now(app_timezone).isoformat()
    if stats.get("first_run") is None:
        stats["first_run"] = now
    stats["last_run"] = now
    save_stats(stats)


def human_bytes(num: int) -> str:
    """Convert bytes to human-readable format (B, KB, MB, GB, TB, PB)."""
    n = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def format_time(time_str: str) -> str:
    """Format time string according to user preference (12h or 24h)."""
    if use_24h_format:
        return time_str
    # Convert 24h to 12h format
    try:
        parts = time_str.split(":", 1)
        hour = int(parts[0])
        minute = parts[1] if len(parts) > 1 else "00"
        if hour == 0:
            return f"12:{minute} AM"
        elif hour < 12:
            return f"{hour}:{minute} AM"
        elif hour == 12:
            return f"12:{minute} PM"
        else:
            return f"{hour - 12}:{minute} PM"
    except Exception:
        return time_str


def describe_schedule() -> str:
    """Generate a human-readable description of the current schedule."""
    freq = config.get("frequency", "daily")
    time_str = config.get("time", "03:00")
    formatted_time = format_time(time_str)

    if freq == "daily":
        return f"daily at {formatted_time} ({tz_name})"
    if freq == "weekly":
        day_key = config.get("day_of_week", "mon")
        day_names = {
            "mon": "Monday",
            "tue": "Tuesday",
            "wed": "Wednesday",
            "thu": "Thursday",
            "fri": "Friday",
            "sat": "Saturday",
            "sun": "Sunday",
        }
        return f"weekly at {day_names.get(day_key, day_key)} {formatted_time} ({tz_name})"
    if freq == "monthly":
        day_of_month = config.get("day_of_month", 1)
        return f"monthly on day {day_of_month} at {formatted_time} ({tz_name})"
    return f"{freq} at {formatted_time} ({tz_name})"


def validate_time(s: str) -> str:
    """Validate HH:MM time format and clamp to valid 24h range on parse errors."""
    try:
        parts = s.split(":", 1)
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 else 0
    except Exception as e:
        log(f"Invalid time format '{s}': {e}. Falling back to 03:00")
        h, m = 3, 0
    h = max(0, min(23, h))
    m = max(0, min(59, m))
    return f"{h:02d}:{m:02d}"


def _deep_merge(base: dict, override: dict) -> None:
    """Deep merge override dict into base dict, preserving nested structures.

    This ensures that nested dicts like notifications.gotify and notifications.ntfy
    are merged individually rather than being completely replaced.

    Example:
    base = {"notifications": {"gotify": {...}, "ntfy": {...}}}
    override = {"notifications": {"provider": "ntfy"}}
    Result: base keeps gotify and ntfy sub-dicts, only updates provider field
    """
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            # Recursively merge nested dicts
            _deep_merge(base[key], value)
        else:
            # Overwrite primitives and lists
            base[key] = value


def effective_config():
    """Return the current effective configuration with relevant fields."""
    freq = config.get("frequency", "daily")
    base = {
        "schedule_enabled": config.get("schedule_enabled", True),
        "frequency": freq,
        "time": config.get("time"),
        "prune_containers": config.get("prune_containers"),
        "prune_images": config.get("prune_images"),
        "prune_networks": config.get("prune_networks"),
        "prune_volumes": config.get("prune_volumes"),
        "prune_build_cache": config.get("prune_build_cache"),
        "docker_hosts": config.get("docker_hosts"),
        "notifications": config.get("notifications"),
    }
    if freq == "weekly":
        base["day_of_week"] = config.get("day_of_week")
    elif freq == "monthly":
        base["day_of_month"] = config.get("day_of_month")
    return base


def load_config(silent=False):
    """Load configuration from disk with deep merge. Set silent=True to suppress logging."""
    global config
    with config_lock:
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = json.loads(json.dumps(DEFAULT_CONFIG))
            # Deep merge: preserve nested structures like notifications.gotify, notifications.ntfy
            _deep_merge(merged, data)

            # Migrate legacy notification keys into new notifications structure (best-effort)
            # Only migrate if new structure doesn't exist in loaded config
            if "notifications" not in data:
                # Check if we have any legacy notification keys to migrate
                has_gotify_keys = any(k in data for k in ("gotify_enabled", "gotify_url", "gotify_token"))
                has_ntfy_keys = any(k in data for k in ("ntfy_enabled", "ntfy_url", "ntfy_topic", "ntfy_token"))
                has_discord_keys = any(k in data for k in ("discord_enabled", "discord_webhook_url"))

                if has_gotify_keys or has_ntfy_keys or has_discord_keys:
                    # Ensure notifications exists with defaults before migration
                    if "notifications" not in merged:
                        merged["notifications"] = json.loads(json.dumps(DEFAULT_CONFIG["notifications"]))

                    # Migrate Gotify settings if present
                    if has_gotify_keys:
                        got = {
                            "enabled": bool(data.get("gotify_enabled")),
                            "url": (data.get("gotify_url") or "").strip(),
                            "token": (data.get("gotify_token") or "").strip(),
                        }
                        merged["notifications"]["gotify"] = got

                    # Migrate ntfy settings if present
                    if has_ntfy_keys:
                        ntf = {
                            "enabled": bool(data.get("ntfy_enabled")),
                            "url": (data.get("ntfy_url") or "").strip(),
                            "topic": (data.get("ntfy_topic") or "").strip(),
                            "token": (data.get("ntfy_token") or "").strip(),
                        }
                        merged["notifications"]["ntfy"] = ntf

                    # Migrate Discord settings if present
                    if has_discord_keys:
                        disc = {
                            "enabled": bool(data.get("discord_enabled")),
                            "webhook_url": (data.get("discord_webhook_url") or "").strip(),
                        }
                        merged["notifications"]["discord"] = disc

                    # Migrate provider selection (default to gotify for backwards compatibility)
                    if has_discord_keys and data.get("discord_enabled"):
                        merged["notifications"]["provider"] = "discord"
                    elif has_ntfy_keys and data.get("ntfy_enabled"):
                        merged["notifications"]["provider"] = "ntfy"
                    elif has_gotify_keys:
                        merged["notifications"]["provider"] = "gotify"

                    # Migrate only_on_changes setting (check both legacy keys, prefer gotify)
                    if "gotify_only_on_changes" in data:
                        merged["notifications"]["only_on_changes"] = bool(data["gotify_only_on_changes"])
                    elif "ntfy_only_on_changes" in data:
                        merged["notifications"]["only_on_changes"] = bool(data["ntfy_only_on_changes"])

            # Ensure notifications key exists with all required subkeys
            if "notifications" not in merged:
                merged["notifications"] = json.loads(json.dumps(DEFAULT_CONFIG["notifications"]))

            # Ensure all provider subkeys exist (forward compatibility for new providers like telegram & pushover)
            for provider_key in ["gotify", "ntfy", "discord", "telegram", "pushover"]:
                if provider_key not in merged["notifications"]:
                    merged["notifications"][provider_key] = json.loads(
                        json.dumps(DEFAULT_CONFIG["notifications"][provider_key])
                    )

            # Migrate numeric priority (1-10) to text priority (low/medium/high)
            priority = merged.get("notifications", {}).get("priority")
            if isinstance(priority, int):
                # Map: 1-3 -> low, 4-7 -> medium, 8-10 -> high
                if priority <= 3:
                    merged["notifications"]["priority"] = "low"
                elif priority <= 7:
                    merged["notifications"]["priority"] = "medium"
                else:
                    merged["notifications"]["priority"] = "high"
            elif not isinstance(priority, str) or priority not in ["low", "medium", "high"]:
                # Invalid or missing priority, set to default
                merged["notifications"]["priority"] = "medium"

            # Ensure docker_hosts exists and has valid structure
            if "docker_hosts" not in merged or not isinstance(merged["docker_hosts"], list):
                merged["docker_hosts"] = json.loads(json.dumps(DEFAULT_CONFIG["docker_hosts"]))

            # Clean up: remove Local/unix:// entries that shouldn't be persisted
            merged["docker_hosts"] = [
                h
                for h in merged["docker_hosts"]
                if h.get("name") != "Local" and "unix://" not in h.get("url", "")
            ]

            # Validate each remaining host entry has required fields
            for host in merged["docker_hosts"]:
                if "name" not in host:
                    host["name"] = "Unnamed"
                if "url" not in host:
                    host["url"] = "tcp://localhost:2375"
                if "enabled" not in host:
                    host["enabled"] = True

            config = merged
            if not silent:
                log(f"Loaded config from {CONFIG_PATH}: {_redact_for_log(effective_config())}")
        except FileNotFoundError:
            if not silent:
                log(f"No config file found at {CONFIG_PATH}, using defaults.")
            config = json.loads(json.dumps(DEFAULT_CONFIG))
        except Exception as e:
            if not silent:
                log(f"Error loading config from {CONFIG_PATH}: {e}. Using defaults.")
            config = json.loads(json.dumps(DEFAULT_CONFIG))


def save_config():
    """Atomic save with fsync and restricted permissions (best-effort)."""
    with config_lock:
        try:
            path = Path(CONFIG_PATH)
            parent = path.parent or Path(".")
            parent.mkdir(parents=True, exist_ok=True)

            # Clean up docker_hosts: remove Local/unix:// entries before saving
            config_to_save = json.loads(json.dumps(config))
            if "docker_hosts" in config_to_save:
                config_to_save["docker_hosts"] = [
                    h
                    for h in config_to_save["docker_hosts"]
                    if h.get("name") != "Local" and "unix://" not in h.get("url", "")
                ]

            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    "w", delete=False, dir=str(parent), encoding="utf-8"
                ) as tmp:
                    json.dump(config_to_save, tmp, indent=2)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                    tmp_path = Path(tmp.name)

                # try to restrict permissions (best-effort)
                try:
                    tmp_path.chmod(0o600)
                except Exception:
                    pass

                # atomic replace
                tmp_path.replace(path)
                log(f"Config saved to {path}: {_redact_for_log(config_to_save)}")
            finally:
                # cleanup leftover temp if any
                if tmp_path and tmp_path.exists() and tmp_path != path:
                    try:
                        tmp_path.unlink()
                    except Exception:
                        pass
        except Exception as e:
            log(f"Failed to save config to {CONFIG_PATH}: {e}")


def _send_gotify(cfg: dict, title: str, message: str, priority: str = "medium") -> bool:
    """Send a notification via Gotify."""
    if not cfg.get("enabled"):
        log("Gotify disabled; skipping notification.")
        return False

    url = (cfg.get("url") or "").strip()
    token = (cfg.get("token") or "").strip()
    if not url or not token:
        log("Gotify enabled but URL/token missing; skipping.")
        return False

    # Map priority: low=2, medium=5, high=8
    priority_map = {"low": 2, "medium": 5, "high": 8}
    gotify_priority = priority_map.get(priority, 2)

    endpoint = url.rstrip("/") + "/message?token=" + token
    payload = json.dumps({"title": title, "message": message, "priority": gotify_priority}).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            log(f"Gotify notification sent, status={getattr(resp, 'status', '?')}")
            return True
    except Exception as e:
        log(f"Failed to send Gotify notification: {e}")
        return False


def _send_ntfy(cfg: dict, title: str, message: str, priority: str = "medium") -> bool:
    """Send a notification via ntfy."""
    if not cfg.get("enabled"):
        log("ntfy disabled; skipping notification.")
        return False

    url = (cfg.get("url") or "").strip()
    topic = (cfg.get("topic") or "").strip()
    token = (cfg.get("token") or "").strip()

    if not url or not topic:
        log("ntfy enabled but URL/topic missing; skipping.")
        return False

    # Map priority: low=2, medium=3, high=5 (ntfy range is 1-5)
    priority_map = {"low": 2, "medium": 3, "high": 5}
    ntfy_priority = priority_map.get(priority, 2)

    # Parse URL to extract authentication
    parsed = urllib.parse.urlparse(url)
    headers = {"Title": title, "Priority": str(ntfy_priority), "Content-Type": "text/plain"}

    # Priority 1: Use explicit token if provided (Bearer token auth)
    if token:
        headers["Authorization"] = f"Bearer {token}"
        endpoint = url.rstrip("/") + "/" + topic.lstrip("/")
    # Priority 2: Check if URL contains username:password (Basic auth)
    elif parsed.username or parsed.password:
        # Reconstruct URL without credentials
        clean_url = urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.hostname + (f":{parsed.port}" if parsed.port else ""),
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        # Add Basic Auth header
        username = parsed.username or ""
        password = parsed.password or ""
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded_credentials}"
        endpoint = clean_url.rstrip("/") + "/" + topic.lstrip("/")
    else:
        # No authentication
        endpoint = url.rstrip("/") + "/" + topic.lstrip("/")

    payload = message.encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            log(f"ntfy notification sent, status={getattr(resp, 'status', '?')}")
            return True
    except Exception as e:
        log(f"Failed to send ntfy notification: {e}")
        return False


def _send_discord(cfg: dict, title: str, message: str, priority: str = "medium") -> bool:
    """Send a notification via Discord webhook."""
    if not cfg.get("enabled"):
        log("Discord disabled; skipping notification.")
        return False

    webhook_url = (cfg.get("webhook_url") or "").strip()
    if not webhook_url:
        log("Discord enabled but webhook_url missing; skipping.")
        return False

    # Validate webhook URL format
    if not webhook_url.startswith("https://discord.com/api/webhooks/") and not webhook_url.startswith(
        "https://discordapp.com/api/webhooks/"
    ):
        log(f"Invalid Discord webhook URL format: {webhook_url[:50]}...")
        return False

    # Map priority to Discord color (embed left border color)
    # low: green (info), medium: orange (warning), high: red (critical)
    color_map = {
        "low": 0x2ECC71,  # Green
        "medium": 0xF39C12,  # Orange
        "high": 0xE74C3C,  # Red
    }
    embed_color = color_map.get(priority, 0x2ECC71)  # Default: Green

    # Format message for Discord (preserve line breaks)
    payload = {
        "embeds": [
            {
                "title": title,
                "description": message,
                "color": embed_color,
                "timestamp": datetime.datetime.now(app_timezone).isoformat(),
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")
    # Discord requires proper headers including User-Agent
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "PruneMate/1.3.0 (Docker cleanup bot)",
    }

    req = urllib.request.Request(webhook_url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            log(f"Discord notification sent, status={getattr(resp, 'status', '?')}")
            return True
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        log(f"Discord webhook HTTP error {e.code}: {e.reason}. Body: {error_body[:200]}")
        return False
    except urllib.error.URLError as e:
        log(f"Discord webhook network error: {e.reason}")
        return False
    except Exception as e:
        log(f"Failed to send Discord notification: {e}")
        return False


def _send_telegram(cfg: dict, title: str, message: str, priority: str = "medium") -> bool:
    """Send a notification via Telegram Bot API."""
    if not cfg.get("enabled"):
        log("Telegram disabled; skipping notification.")
        return False

    bot_token = (cfg.get("bot_token") or "").strip()
    chat_id = (cfg.get("chat_id") or "").strip()
    if not bot_token or not chat_id:
        log("Telegram enabled but bot_token/chat_id missing; skipping.")
        return False

    # Telegram doesn't have native priority support
    # We use disable_notification for low priority (silent), normal for medium/high
    disable_notification = priority == "low"

    # Format message with title
    full_message = f"{title}\n\n{message}"

    # Telegram Bot API endpoint
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps(
        {
            "chat_id": chat_id,
            "text": full_message,
            "parse_mode": "HTML",
            "disable_notification": disable_notification,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "PruneMate/1.3.0 (Docker cleanup bot)",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("ok"):
                log(
                    f"Telegram notification sent, message_id={result.get('result', {}).get('message_id', '?')}"
                )
                return True
            else:
                log(f"Telegram API returned ok=false: {result}")
                return False
    except Exception as e:
        log(f"Failed to send Telegram notification: {e}")
        return False


def _send_pushover(cfg: dict, title: str, message: str, priority: str = "medium") -> bool:
    """Send a notification via Pushover."""
    if not cfg.get("enabled"):
        log("Pushover disabled; skipping notification.")
        return False

    token = (cfg.get("token") or "").strip()
    user_key = (cfg.get("user_key") or "").strip()

    if not token or not user_key:
        log("Pushover enabled but token/user_key missing; skipping.")
        return False

    # Map PruneMate priority (low/medium/high) to Pushover priority (-1, 0, 1)
    priority_map = {"low": -1, "medium": 0, "high": 1}
    pushover_priority = priority_map.get(priority, 0)

    # Pushover API endpoint
    endpoint = "https://api.pushover.net/1/messages.json"

    # Pushover expects application/x-www-form-urlencoded
    payload_dict = {
        "token": token,
        "user": user_key,
        "title": title,
        "message": message,
        "priority": str(pushover_priority),
    }

    data = urllib.parse.urlencode(payload_dict).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "PruneMate/1.3.0 (Docker cleanup bot)",
    }

    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = getattr(resp, "status", None)
            # Try to read Pushover JSON response for logging, but ignore failures
            try:
                body = resp.read().decode("utf-8")
            except Exception:
                body = ""
            log(f"Pushover notification sent, status={status}, body={body[:200]}")
            return True
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        log(f"Pushover HTTP error {e.code}: {e.reason}. Body: {error_body[:200]}")
        return False
    except urllib.error.URLError as e:
        log(f"Pushover network error: {e.reason}")
        return False
    except Exception as e:
        log(f"Failed to send Pushover notification: {e}")
        return False


def send_notification(title: str, message: str, priority: str = "medium") -> bool:
    """Send a notification using the configured provider (gotify, ntfy, discord, telegram, or pushover)."""
    notcfg = config.get("notifications", DEFAULT_CONFIG["notifications"])
    provider = (notcfg.get("provider") or "gotify").lower()

    if provider == "gotify":
        return _send_gotify(notcfg.get("gotify", {}), title, message, priority)
    if provider == "ntfy":
        return _send_ntfy(notcfg.get("ntfy", {}), title, message, priority)
    if provider == "discord":
        return _send_discord(notcfg.get("discord", {}), title, message, priority)
    if provider == "telegram":
        return _send_telegram(notcfg.get("telegram", {}), title, message, priority)
    if provider == "pushover":
        return _send_pushover(notcfg.get("pushover", {}), title, message, priority)

    log(f"Unknown notification provider '{provider}'; skipping.")
    return False


def create_docker_client(host_url: str):
    """Create a Docker client for the given host URL.

    Args:
        host_url: Docker host URL (e.g., 'unix:///var/run/docker.sock', 'tcp://host:2375')

    Returns:
        Docker client instance or None on failure
    """
    if docker is None:
        log("Docker SDK not available.")
        return None

    try:
        # Support both unix sockets and TCP connections
        if host_url.startswith("unix://"):
            return docker.DockerClient(base_url=host_url)
        elif host_url.startswith("tcp://") or host_url.startswith("http://") or host_url.startswith("https://"):
            return docker.DockerClient(base_url=host_url)
        else:
            # Fallback: try as-is
            return docker.DockerClient(base_url=host_url)
    except Exception as e:
        log(f"Failed to create Docker client for {host_url}: {e}")
        return None


# ... rest of the file (prune preview, routes, run_prune_job, etc.) remain unchanged ...
# For brevity here, keep your original content after this point.

# NOTE: In your real file, keep all remaining code below unchanged.


if __name__ == "__main__":
    # Your existing __main__ entry point code goes here.
    # Keep whatever PruneMate already has.
    pass
