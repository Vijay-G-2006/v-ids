"""
V-IDS Configuration Loader
===========================
Loads configuration from YAML files with CLI overrides and safe defaults.
Handles missing files, malformed YAML, and provides a complete default
configuration that allows the system to operate even without a config file.
"""

import os
import yaml
import logging

logger = logging.getLogger("v-ids.config")

# ── Complete default configuration ──────────────────────────────────────────
DEFAULT_CONFIG = {
    "network": {
        "interface": "",
        "bpf_filter": "",
    },
    "logging": {
        "log_file": "/var/log/v-ids.log",
        "fallback_log_file": "./v-ids.log",
        "log_level": "INFO",
        "colorize_stdout": True,
        "rate_limit_seconds": 30,
    },
    "detection": {
        "port_scan": {
            "enabled": True,
            "unique_ports_threshold": 15,
            "window_seconds": 60,
            "severity": "HIGH",
        },
        "cleartext_creds": {
            "enabled": True,
            "monitored_ports": [21, 23, 80, 110, 143, 8080],
            "patterns": [
                "USER ", "PASS ", "password=", "passwd=",
                "login=", "username=", "pwd=", "Authorization: Basic",
            ],
            "severity": "CRITICAL",
        },
        "icmp_flood": {
            "enabled": True,
            "icmp_threshold": 100,
            "window_seconds": 10,
            "oversized_bytes": 1500,
            "severity": "MEDIUM",
        },
        "ssh_brute_force": {
            "enabled": True,
            "attempt_threshold": 10,
            "window_seconds": 60,
            "target_port": 22,
            "severity": "HIGH",
        },
        "http_threats": {
            "enabled": True,
            "http_ports": [80, 8080, 8443, 8888],
            "severity": "CRITICAL",
        },
    },
    "engine": {
        "queue_size": 10000,
        "cleanup_interval_seconds": 60,
    },
    "dashboard": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8847,
        "max_alerts_history": 500,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """
    Recursively merge `override` into `base`.
    Values in `override` take precedence. Nested dicts are merged, not replaced.
    """
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(config_path: str = None) -> dict:
    """
    Load configuration from a YAML file, merged over defaults.

    Args:
        config_path: Path to a YAML configuration file. If None or missing,
                     returns the default configuration.

    Returns:
        Complete configuration dictionary with all required keys.
    """
    config = DEFAULT_CONFIG.copy()

    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            if isinstance(user_config, dict):
                config = _deep_merge(DEFAULT_CONFIG, user_config)
                logger.info("Loaded configuration from: %s", config_path)
            else:
                logger.warning(
                    "Config file %s did not contain a valid YAML mapping. "
                    "Using defaults.", config_path
                )
        except yaml.YAMLError as e:
            logger.error("Failed to parse config file %s: %s. Using defaults.", config_path, e)
        except OSError as e:
            logger.error("Failed to read config file %s: %s. Using defaults.", config_path, e)
    elif config_path:
        logger.warning("Config file not found: %s. Using defaults.", config_path)

    return config


def apply_cli_overrides(config: dict, interface: str = None,
                        log_file: str = None, verbose: bool = False) -> dict:
    """
    Apply CLI argument overrides on top of the loaded configuration.

    Args:
        config:    Base configuration dictionary.
        interface: Network interface override (e.g., "wlp2s0").
        log_file:  Log file path override.
        verbose:   If True, set log level to DEBUG.

    Returns:
        Updated configuration dictionary.
    """
    if interface:
        config["network"]["interface"] = interface
    if log_file:
        config["logging"]["log_file"] = log_file
    if verbose:
        config["logging"]["log_level"] = "DEBUG"
    return config
