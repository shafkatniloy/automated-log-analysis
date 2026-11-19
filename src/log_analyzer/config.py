from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class DetectionRule:
    id: str
    title: str
    event_type: str
    pattern: Optional[str] = None
    threshold: int = 3
    window_minutes: int = 5
    severity: str = "HIGH"
    recommended_action: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionRule":
        return cls(
            id=str(data.get("id", "UNKNOWN")),
            title=str(data.get("title", "Unnamed Rule")),
            event_type=str(data.get("event_type", "generic")),
            pattern=data.get("pattern"),
            threshold=int(data.get("threshold", 3)),
            window_minutes=int(data.get("window_minutes", 5)),
            severity=str(data.get("severity", "HIGH")).upper(),
            recommended_action=str(data.get("recommended_action", "")),
        )


@dataclass
class RulesConfig:
    default_window_minutes: int = 5
    rules: List[DetectionRule] = field(default_factory=list)

    @classmethod
    def load_from_yaml(cls, path: Path) -> "RulesConfig":
        if not path.exists():
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        analysis_cfg = data.get("analysis", {})
        default_window = int(analysis_cfg.get("default_window_minutes", 5))

        rules_list = [
            DetectionRule.from_dict(r) for r in data.get("rules", [])
        ]
        return cls(default_window_minutes=default_window, rules=rules_list)
