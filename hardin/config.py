import json
from pathlib import Path

from hardin.exceptions import ConfigError

CONFIG_DIR = Path.home() / ".hardin"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    "provider": "gemini",  # 'gemini' or 'openai'
    "api_key": "",
    "model": "gemini-2.5-flash",
    "api_base": "",  # Optional, for OpenAI-compatible proxies
    "output_dir": str(Path.home() / "hardin_reports"),
}


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.touch(exist_ok=True)
    if CONFIG_FILE.stat().st_size == 0:
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG.copy(), f, indent=2)


def load_config() -> dict:
    ensure_config_dir()
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        merged = {**DEFAULT_CONFIG, **data}
        return merged
    except json.JSONDecodeError:
        save_config(DEFAULT_CONFIG.copy())
        return DEFAULT_CONFIG.copy()
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}", code="CONFIG_READ_FAIL") from e


def save_config(config: dict) -> None:
    ensure_config_dir()
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except OSError as e:
        raise ConfigError(f"Cannot write config file: {e}", code="CONFIG_WRITE_FAIL") from e


def get_api_key() -> str:
    config = load_config()
    return config.get("api_key", "")


def set_api_key(key: str) -> None:
    config = load_config()
    config["api_key"] = key
    save_config(config)


def get_model() -> str:
    config = load_config()
    return config.get("model", DEFAULT_CONFIG["model"])

def set_model(model: str) -> None:
    config = load_config()
    config["model"] = model
    save_config(config)

def get_provider() -> str:
    config = load_config()
    return config.get("provider", DEFAULT_CONFIG["provider"])

def set_provider(provider: str) -> None:
    config = load_config()
    config["provider"] = provider
    save_config(config)

def get_api_base() -> str:
    config = load_config()
    return config.get("api_base", DEFAULT_CONFIG["api_base"])

def set_api_base(api_base: str) -> None:
    config = load_config()
    config["api_base"] = api_base
    save_config(config)


def get_output_dir() -> Path:
    config = load_config()
    return Path(config.get("output_dir", DEFAULT_CONFIG["output_dir"]))
