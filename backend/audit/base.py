from typing import List, Dict, Any
from backend.models.network_model import NetworkModel

class AuditPlugin:
    """Base class for all MikroTik configuration audit rules/checks."""
    id: str = "BP-000"
    category: str = "general"
    severity: str = "info"  # critical, high, medium, low, info
    confidence: int = 100   # 0-100%

    title: str = "Default Plugin"
    description: str = ""
    impact: str = ""
    best_practice: str = ""
    resolution: str = ""

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        """
        Execute check and return findings.
        Returns:
            {
                "issues": [str],
                "warnings": [str],
                "fixes": [str],
                "info": [str],
                "recs": [str]
            }
        """
        return {
            "issues": [],
            "warnings": [],
            "fixes": [],
            "info": [],
            "recs": []
        }

class AuditRegistry:
    def __init__(self):
        self._plugins: List[AuditPlugin] = []

    def register(self, plugin_cls):
        self._plugins.append(plugin_cls())
        return plugin_cls

    def get_plugins(self) -> List[AuditPlugin]:
        return self._plugins

registry = AuditRegistry()
