"""
Configuration handling for Zetton.

This module provides centralized configuration management for the Zetton
framework, including backend settings, analysis parameters, and user
preferences. Supports TOML configuration files and environment variables.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default configuration directory
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "zetton"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "zetton.toml"


class LogLevel(Enum):
    """Supported log levels."""
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()

    def to_python_level(self) -> int:
        """Convert to Python logging level."""
        mapping = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL,
        }
        return mapping[self]


@dataclass
class QuantumConfig:
    """Configuration for quantum computing backends."""
    default_backend: str = "simulator_aer"
    shots: int = 1024
    optimization_level: int = 1
    max_qubits: int = 20
    seed: int | None = None
    ibm_token: str = ""
    ibm_instance: str = ""
    aws_region: str = "us-east-1"
    aws_device_arn: str = ""
    noise_model: str | None = None
    error_mitigation: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuantumConfig:
        """Create QuantumConfig from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class AnalysisConfig:
    """Configuration for analysis parameters."""
    max_instructions: int = 1_000_000
    entropy_window_size: int = 256
    entropy_threshold: float = 7.5
    recursive_descent: bool = True
    follow_calls: bool = True
    max_function_size: int = 100_000
    timeout_seconds: int = 300
    parallel_workers: int = 0  # 0 = auto (cpu_count)
    cfg_max_depth: int = 50
    dataflow_max_iterations: int = 100

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisConfig:
        """Create AnalysisConfig from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class ForensicsConfig:
    """Configuration for forensics modules."""
    report_format: str = "html"  # html, json, pdf
    include_disassembly: bool = True
    include_strings: bool = True
    include_entropy_map: bool = True
    timeline_resolution: str = "second"  # second, minute, hour
    max_timeline_events: int = 10_000
    yara_rules_path: str = ""
    volatility_path: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ForensicsConfig:
        """Create ForensicsConfig from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class OutputConfig:
    """Configuration for output and display."""
    color_output: bool = True
    verbose: bool = False
    log_level: str = "INFO"
    output_directory: str = "./zetton_output"
    save_intermediate: bool = False
    json_indent: int = 2

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OutputConfig:
        """Create OutputConfig from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class ZettonConfig:
    """
    Master configuration for the Zetton framework.

    Aggregates all sub-configurations and provides methods for loading
    from files, environment variables, and programmatic overrides.

    Configuration precedence (highest to lowest):
    1. Programmatic overrides
    2. Environment variables (ZETTON_*)
    3. Project-level config (./zetton.toml)
    4. User-level config (~/.config/zetton/zetton.toml)
    5. Default values

    Example:
        >>> config = ZettonConfig.load()
        >>> config.quantum.shots = 2048
        >>> config.save()
    """
    quantum: QuantumConfig = field(default_factory=QuantumConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    forensics: ForensicsConfig = field(default_factory=ForensicsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    plugins: list[str] = field(default_factory=list)
    _config_path: Path | None = field(default=None, repr=False)

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> ZettonConfig:
        """
        Load configuration with full precedence chain.

        Args:
            config_path: Explicit config file path (overrides search)

        Returns:
            Loaded ZettonConfig instance
        """
        config = cls()

        # 1. Load from user-level config
        if DEFAULT_CONFIG_FILE.exists():
            config._merge_from_file(DEFAULT_CONFIG_FILE)

        # 2. Load from project-level config
        project_config = Path("zetton.toml")
        if project_config.exists():
            config._merge_from_file(project_config)

        # 3. Load from explicit path
        if config_path is not None:
            path = Path(config_path)
            if path.exists():
                config._merge_from_file(path)
                config._config_path = path
            else:
                logger.warning(f"Config file not found: {path}")

        # 4. Apply environment variable overrides
        config._apply_env_overrides()

        return config

    def _merge_from_file(self, path: Path) -> None:
        """Merge configuration from a TOML file."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore
            except ImportError:
                # Fall back to basic parsing if no TOML library
                logger.warning(
                    "No TOML library available. Install tomli: "
                    "pip install tomli"
                )
                return

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            logger.error(f"Failed to parse config file {path}: {e}")
            return

        if "quantum" in data:
            self.quantum = QuantumConfig.from_dict(data["quantum"])
        if "analysis" in data:
            self.analysis = AnalysisConfig.from_dict(data["analysis"])
        if "forensics" in data:
            self.forensics = ForensicsConfig.from_dict(data["forensics"])
        if "output" in data:
            self.output = OutputConfig.from_dict(data["output"])
        if "plugins" in data:
            self.plugins = data["plugins"]

        logger.debug(f"Loaded configuration from {path}")

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides (ZETTON_* prefix)."""
        env_mapping = {
            "ZETTON_QUANTUM_BACKEND": ("quantum", "default_backend"),
            "ZETTON_QUANTUM_SHOTS": ("quantum", "shots", int),
            "ZETTON_QUANTUM_MAX_QUBITS": ("quantum", "max_qubits", int),
            "ZETTON_IBM_TOKEN": ("quantum", "ibm_token"),
            "ZETTON_IBM_INSTANCE": ("quantum", "ibm_instance"),
            "ZETTON_AWS_REGION": ("quantum", "aws_region"),
            "ZETTON_AWS_DEVICE_ARN": ("quantum", "aws_device_arn"),
            "ZETTON_LOG_LEVEL": ("output", "log_level"),
            "ZETTON_OUTPUT_DIR": ("output", "output_directory"),
            "ZETTON_VERBOSE": ("output", "verbose", bool),
            "ZETTON_YARA_RULES": ("forensics", "yara_rules_path"),
            "ZETTON_VOLATILITY_PATH": ("forensics", "volatility_path"),
            "ZETTON_MAX_INSTRUCTIONS": ("analysis", "max_instructions", int),
            "ZETTON_TIMEOUT": ("analysis", "timeout_seconds", int),
        }

        for env_var, mapping in env_mapping.items():
            value = os.environ.get(env_var)
            if value is None:
                continue

            section_name = mapping[0]
            attr_name = mapping[1]
            converter = mapping[2] if len(mapping) > 2 else str

            try:
                if converter == bool:
                    converted = value.lower() in ("true", "1", "yes")
                else:
                    converted = converter(value)

                section = getattr(self, section_name)
                setattr(section, attr_name, converted)
                logger.debug(f"Applied env override: {env_var}={converted}")
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid env value for {env_var}: {e}")

    def save(self, path: str | Path | None = None) -> None:
        """
        Save configuration to a TOML file.

        Args:
            path: Output path. Defaults to user config location.
        """
        if path is None:
            path = self._config_path or DEFAULT_CONFIG_FILE

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Build TOML content manually to avoid dependency on tomli_w
        lines = [
            "# Zetton Configuration",
            "# Generated by Zetton framework",
            "",
        ]

        sections = {
            "quantum": self.quantum,
            "analysis": self.analysis,
            "forensics": self.forensics,
            "output": self.output,
        }

        for section_name, section_obj in sections.items():
            lines.append(f"[{section_name}]")
            for field_name, field_val in section_obj.__dict__.items():
                if field_name.startswith("_"):
                    continue
                if isinstance(field_val, str):
                    lines.append(f'{field_name} = "{field_val}"')
                elif isinstance(field_val, bool):
                    lines.append(f"{field_name} = {'true' if field_val else 'false'}")
                elif field_val is None:
                    continue  # Skip None values
                else:
                    lines.append(f"{field_name} = {field_val}")
            lines.append("")

        if self.plugins:
            lines.append("[plugins]")
            plugins_str = ", ".join(f'"{p}"' for p in self.plugins)
            lines.append(f"enabled = [{plugins_str}]")
            lines.append("")

        path.write_text("\n".join(lines))
        logger.info(f"Configuration saved to {path}")

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        result = {}
        for section_name in ("quantum", "analysis", "forensics", "output"):
            section = getattr(self, section_name)
            result[section_name] = {
                k: v for k, v in section.__dict__.items()
                if not k.startswith("_")
            }
        result["plugins"] = self.plugins
        return result

    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> ZettonConfig:
        """Create configuration from JSON string."""
        data = json.loads(json_str)
        config = cls()
        if "quantum" in data:
            config.quantum = QuantumConfig.from_dict(data["quantum"])
        if "analysis" in data:
            config.analysis = AnalysisConfig.from_dict(data["analysis"])
        if "forensics" in data:
            config.forensics = ForensicsConfig.from_dict(data["forensics"])
        if "output" in data:
            config.output = OutputConfig.from_dict(data["output"])
        if "plugins" in data:
            config.plugins = data["plugins"]
        return config

    def setup_logging(self) -> None:
        """Configure logging based on output settings."""
        level = getattr(logging, self.output.log_level.upper(), logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

        root_logger = logging.getLogger("zetton")
        root_logger.setLevel(level)
        root_logger.addHandler(handler)

        if self.output.verbose:
            root_logger.setLevel(logging.DEBUG)

    def validate(self) -> list[str]:
        """
        Validate configuration and return list of warnings.

        Returns:
            List of warning messages (empty if config is valid)
        """
        warnings = []

        if self.quantum.shots < 1:
            warnings.append("quantum.shots must be >= 1")
        if self.quantum.shots > 100_000:
            warnings.append("quantum.shots > 100000 may be slow")
        if self.quantum.max_qubits > 30:
            warnings.append(
                "quantum.max_qubits > 30 requires significant memory"
            )
        if self.analysis.timeout_seconds < 1:
            warnings.append("analysis.timeout_seconds must be >= 1")
        if self.analysis.entropy_threshold < 0 or self.analysis.entropy_threshold > 8:
            warnings.append("analysis.entropy_threshold must be between 0 and 8")
        if self.output.log_level.upper() not in (
            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
        ):
            warnings.append(f"Invalid log level: {self.output.log_level}")

        # Check for quantum backend credentials
        if self.quantum.default_backend == "ibm_quantum" and not self.quantum.ibm_token:
            warnings.append(
                "IBM Quantum backend selected but no token set. "
                "Set ZETTON_IBM_TOKEN or quantum.ibm_token"
            )
        if self.quantum.default_backend == "aws_braket" and not self.quantum.aws_device_arn:
            warnings.append(
                "AWS Braket backend selected but no device ARN set. "
                "Set ZETTON_AWS_DEVICE_ARN or quantum.aws_device_arn"
            )

        return warnings


def get_default_config() -> ZettonConfig:
    """Get configuration with all default values."""
    return ZettonConfig()


def generate_default_config(path: str | Path | None = None) -> Path:
    """
    Generate a default configuration file.

    Args:
        path: Output path. Defaults to ~/.config/zetton/zetton.toml

    Returns:
        Path to generated config file
    """
    config = ZettonConfig()
    save_path = Path(path) if path else DEFAULT_CONFIG_FILE
    config.save(save_path)
    return save_path
