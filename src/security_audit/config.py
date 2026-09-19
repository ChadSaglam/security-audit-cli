"""Project-level configuration: .security-audit.toml"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_NAME = ".security-audit.toml"


@dataclass
class Config:
    skip_dirs: set[str] = field(default_factory=set)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    role_overrides: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> "Config":
        path = root / CONFIG_NAME
        if not path.exists():
            return cls()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return cls(
            skip_dirs=set(data.get("skip_dirs", [])),
            severity_overrides=dict(data.get("severity_overrides", {})),
            role_overrides=dict(data.get("role_overrides", {})),
        )
