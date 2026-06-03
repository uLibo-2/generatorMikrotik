# -*- coding: utf-8 -*-
from typing import List, Dict, Any
from backend.parsers.ast_parser import RouterOS_AST

class VersionCompatibilityEngine:
    # Feature mappings with introduced/deprecated/removed versions
    COMPATIBILITY_RULES = {
        "/interface wifi": {
            "feature_name": "Wi-Fi (wifi-qcom) драйвери",
            "introduced": 7.13,
            "deprecated": None,
            "removed": None,
            "alternative": "Використовуйте RouterOS v7.13 або новіше."
        },
        "/interface wifi configuration": {
            "feature_name": "Wi-Fi 6 Configuration",
            "introduced": 7.13,
            "deprecated": None,
            "removed": None,
            "alternative": "Вимагає RouterOS v7.13+"
        },
        "/interface wireless": {
            "feature_name": "Застарілі Wireless драйвери",
            "introduced": 5.0,
            "deprecated": 7.13,
            "removed": 8.0,
            "alternative": "Рекомендується перехід на '/interface wifi' для Wi-Fi 6 пристроїв на RouterOS v7.13+."
        },
        "/caps-man": {
            "feature_name": "Класичний CAPsMAN",
            "introduced": 6.0,
            "deprecated": 7.13,
            "removed": 8.0,
            "alternative": "Рекомендується використовувати '/interface wifi capsman' (новий CAPsMAN) для RouterOS v7.13+."
        },
        "/container": {
            "feature_name": "Docker Контейнери",
            "introduced": 7.4,
            "deprecated": None,
            "removed": None,
            "alternative": "Вимагає архітектуру arm/arm64 та RouterOS v7.4+."
        },
        "/zerotier": {
            "feature_name": "ZeroTier VPN",
            "introduced": 7.1,
            "deprecated": None,
            "removed": None,
            "alternative": "Вимагає RouterOS v7.1+ на arm/arm64."
        }
    }

    @staticmethod
    def check_compatibility(ast: RouterOS_AST, target_version: float) -> List[Dict[str, Any]]:
        warnings = []

        # Traverse AST nodes to find features
        detected_paths = set(node.path for node in ast.nodes)

        for path, rule in VersionCompatibilityEngine.COMPATIBILITY_RULES.items():
            if any(p.startswith(path) for p in detected_paths):
                # 1. Check if feature was not yet introduced in target version
                if rule["introduced"] and target_version < rule["introduced"]:
                    warnings.append({
                        "type": "error",
                        "severity": "danger",
                        "message": f"Несумісність версії: Функція '{rule['feature_name']}' ({path}) представлена тільки з версії {rule['introduced']}, але виявлено RouterOS {target_version}.",
                        "alternative": rule["alternative"]
                    })
                # 2. Check if feature is removed in target version
                elif rule["removed"] and target_version >= rule["removed"]:
                    warnings.append({
                        "type": "error",
                        "severity": "danger",
                        "message": f"Видалена функція: Функція '{rule['feature_name']}' ({path}) повністю видалена у версії {rule['removed']}. Поточна версія {target_version}.",
                        "alternative": rule["alternative"]
                    })
                # 3. Check if feature is deprecated in target version
                elif rule["deprecated"] and target_version >= rule["deprecated"]:
                    warnings.append({
                        "type": "warning",
                        "severity": "warning",
                        "message": f"Застаріла функція: Функція '{rule['feature_name']}' ({path}) є застарілою починаючи з версії {rule['deprecated']}. Поточна версія {target_version}.",
                        "alternative": rule["alternative"]
                    })

        return warnings
