# -*- coding: utf-8 -*-
import os
import yaml

KB_DIR = os.path.dirname(os.path.abspath(__file__))

class RouterOSKB:
    @staticmethod
    def get_rules() -> dict:
        rules_dict = {"routeros": {}}
        rules_path = os.path.join(KB_DIR, "rules")
        if not os.path.exists(rules_path):
            return rules_dict
        try:
            for file in os.listdir(rules_path):
                if file.endswith(".yaml") or file.endswith(".yml"):
                    name = os.path.splitext(file)[0]
                    # Map 'vlan' file to 'bridge' domain for backwards compatibility
                    target_name = "bridge" if name == "vlan" else name
                    path = os.path.join(rules_path, file)
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                        # Map 'filtering' under 'vlan' to 'vlan-filtering'
                        if target_name == "bridge" and "filtering" in data:
                            data["vlan-filtering"] = data.pop("filtering")
                        rules_dict["routeros"][target_name] = data
            return rules_dict
        except Exception:
            return rules_dict

    @staticmethod
    def get_models() -> dict:
        models_dict = {}
        models_path = os.path.join(KB_DIR, "models")
        if not os.path.exists(models_path):
            return models_dict
        try:
            for file in os.listdir(models_path):
                if file.endswith(".yaml") or file.endswith(".yml"):
                    # Use name of file as the key (e.g. hAP_ax3)
                    path = os.path.join(models_path, file)
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}

                        # Find original key or reconstruct it from filename
                        name_key = os.path.splitext(file)[0]
                        # Retain uppercase for standard model keys
                        for standard_key in ["hAP_ax3", "RB5009", "hAP_ax2", "hAP_ax_lite", "hAP_ac3", "hAP_ac2", "RB4011", "CCR2004", "CCR2116", "CCR2216", "CRS326", "CRS328", "CRS310", "CRS504", "cAP_ax", "wAP_ax", "L009", "hEX_S", "hEX_refresh"]:
                            if name_key.lower() == standard_key.lower():
                                name_key = standard_key
                                break

                        # Add legacy support properties
                        if "hardware" in data:
                            data["cpu"] = {
                                "model": data["hardware"].get("cpu", "Unknown"),
                                "cores": data["hardware"].get("cores", 1),
                                "frequency": data["hardware"].get("frequency", 800)
                            }
                            data["ram"] = {
                                "size_mb": data["hardware"].get("ram_mb", 512)
                            }
                        if "throughput" in data:
                            data["performance"] = {
                                "routing_gbps": data["throughput"].get("routing_gbps", 1.0),
                                "firewall_gbps": data["throughput"].get("firewall_gbps", 1.0),
                                "ipsec_gbps": data["throughput"].get("ipsec_gbps", 0.5)
                            }
                        if "best_use_cases" in data and len(data["best_use_cases"]) > 0:
                            if "wiki" not in data:
                                data["wiki"] = {}
                            data["wiki"]["brief"] = f"Рекомендовано для: {', '.join(data['best_use_cases'])}"

                        # Ensure capability properties exist
                        if "capabilities" in data:
                            if "wireguard_throughput" not in data["capabilities"] and "throughput" in data:
                                data["capabilities"]["wireguard_throughput"] = data["throughput"].get("wireguard_mbps", 100)
                            # Ensure container compatibility
                            data["capabilities"]["container"] = data.get("features", {}).get("containers_supported", False)
                            data["capabilities"]["docker"] = data.get("features", {}).get("containers_supported", False)

                        models_dict[name_key] = data
            return models_dict
        except Exception:
            return models_dict

    @staticmethod
    def get_best_practices() -> dict:
        bp_dict = {}
        bp_path = os.path.join(KB_DIR, "best_practices")
        if not os.path.exists(bp_path):
            return bp_dict
        try:
            for file in os.listdir(bp_path):
                if file.endswith(".yaml") or file.endswith(".yml"):
                    name = os.path.splitext(file)[0]
                    path = os.path.join(bp_path, file)
                    with open(path, "r", encoding="utf-8") as f:
                        bp_dict[name] = yaml.safe_load(f) or {}
            return bp_dict
        except Exception:
            return bp_dict

    @staticmethod
    def get_known_issues() -> dict:
        ki_dict = {}
        ki_path = os.path.join(KB_DIR, "known_issues")
        if not os.path.exists(ki_path):
            return ki_dict
        try:
            for file in os.listdir(ki_path):
                if file.endswith(".yaml") or file.endswith(".yml"):
                    name = os.path.splitext(file)[0]
                    # Map ros_7_15 -> 7.15 or similar
                    version_key = name.replace("ros_", "").replace("_", ".")
                    path = os.path.join(ki_path, file)
                    with open(path, "r", encoding="utf-8") as f:
                        ki_dict[version_key] = yaml.safe_load(f) or []
            return ki_dict
        except Exception:
            return ki_dict

    @staticmethod
    def get_learning() -> dict:
        learn_dict = {}
        learn_path = os.path.join(KB_DIR, "learning")
        if not os.path.exists(learn_path):
            return learn_dict
        try:
            for file in os.listdir(learn_path):
                if file.endswith(".yaml") or file.endswith(".yml"):
                    name = os.path.splitext(file)[0]
                    path = os.path.join(learn_path, file)
                    with open(path, "r", encoding="utf-8") as f:
                        learn_dict[name] = yaml.safe_load(f) or {}
            return learn_dict
        except Exception:
            return learn_dict
