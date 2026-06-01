from typing import Dict, Any, List
import json
from backend.models.network_model import NetworkModel
from backend.parsers.network_model import parse_to_model
from backend.audit.base import registry
# Import plugins so they register
import backend.audit.l2
import backend.audit.l3
import backend.audit.wifi
import backend.audit.security
import backend.audit.performance
import backend.audit.security_advanced
import backend.audit.l3_advanced
import backend.audit.wifi_advanced
import backend.audit.monitoring
from backend.validators.topology import audit_topology_model

def full_audit(config_text: str) -> dict:
    # 1. Parse configuration to Canonical NetworkModel
    model = parse_to_model(config_text)

    # 2. Setup category maps
    # index.html expects these sub-keys inside the response
    category_map = {
        "summary": {"score": 100, "total_issues": 0, "total_warnings": 0},
        "l2": {"issues": [], "warnings": [], "fixes": [], "info": [], "score": 100},
        "vlan": {"issues": [], "warnings": [], "fixes": [], "info": [], "vlan_ids": []},
        "dhcp": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "routing": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "wifi": {"issues": [], "warnings": [], "fixes": [], "info": [], "recommendations": []},
        "capsman": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "security": {"issues": [], "warnings": [], "fixes": [], "info": [], "recommendations": []},
        "performance": {"issues": [], "warnings": [], "fixes": [], "info": [], "recommendations": []},

        # New Platform v2.5 detailed sub-keys mapping to index.html tabs:
        "vlan_ext": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "dhcp_ext": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "capsman_ext": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "wifi_ext": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "firewall": {"issues": [], "warnings": [], "fixes": [], "info": [], "score": 100},
        "multiwan": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "script": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "security_ext": {"issues": [], "warnings": [], "fixes": [], "info": [], "score": 100},
        "monitoring": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "backup": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "services": {"issues": [], "warnings": [], "fixes": [], "info": []},
        "performance_ext": {"issues": [], "warnings": [], "fixes": [], "info": [], "recommendations": []},
        "orphan_objects": {"issues": [], "warnings": [], "fixes": [], "info": []}
    }

    # Pre-fill VLAN ids
    category_map["vlan"]["vlan_ids"] = [v.vlan_id for v in model.vlans]
    # Build port mapping for vlan table in index.html
    pvid_map = {}
    tagged_map = {}
    untagged_map = {}

    for br in model.bridges:
        for port in br.ports:
            pvid_map[port.interface] = port.pvid
        for vlan in br.vlans:
            for vid in vlan.vlan_ids:
                for iface in vlan.tagged:
                    tagged_map.setdefault(iface, []).append(vid)
                for iface in vlan.untagged:
                    untagged_map.setdefault(iface, []).append(vid)

    category_map["vlan"]["ports"] = {
        "pvid": pvid_map,
        "tagged": tagged_map,
        "untagged": untagged_map
    }

    # 3. Run all registered AuditPlugins
    all_issues = 0
    all_warnings = 0
    critical_failures = []

    for plugin in registry.get_plugins():
        res = plugin.run(model)

        # Accumulate metrics
        issues_cnt = len(res.get("issues", []))
        warns_cnt = len(res.get("warnings", []))
        all_issues += issues_cnt
        all_warnings += warns_cnt

        # Collect critical items
        for issue in res.get("issues", []):
            if plugin.severity == "critical":
                critical_failures.append(issue)

        # Map findings to index.html categories
        cat = plugin.category
        is_firewall_plugin = cat == "security" and "Firewall" in plugin.title

        # Firewall-specific security plugins go to 'firewall' tab only (avoid duplication)
        if is_firewall_plugin:
            target_cat = "firewall"
        else:
            target_cat = cat

        if target_cat in category_map:
            category_map[target_cat]["issues"].extend(res.get("issues", []))
            category_map[target_cat]["warnings"].extend(res.get("warnings", []))
            category_map[target_cat]["fixes"].extend(res.get("fixes", []))
            category_map[target_cat]["info"].extend(res.get("info", []))

            # Map recommendations
            recs = res.get("recs", [])
            if recs and "recommendations" in category_map[target_cat]:
                category_map[target_cat]["recommendations"].extend(recs)

    # 4. Topology Chain Path Validation
    category_map["topology"] = audit_topology_model(model)

    # 5. Production Readiness Scoring
    l2_score = max(0, 100 - len(category_map["l2"]["issues"]) * 30 - len(category_map["l2"]["warnings"]) * 10)
    vlan_score = max(0, 100 - len(category_map["vlan_ext"]["issues"]) * 30 - len(category_map["vlan_ext"]["warnings"]) * 10)
    dhcp_score = max(0, 100 - len(category_map["dhcp_ext"]["issues"]) * 30 - len(category_map["dhcp_ext"]["warnings"]) * 10)
    wifi_score = max(0, 100 - len(category_map["wifi_ext"]["issues"]) * 30 - len(category_map["wifi_ext"]["warnings"]) * 10)
    routing_score = max(0, 100 - len(category_map["routing"]["issues"]) * 30 - len(category_map["routing"]["warnings"]) * 10)
    multiwan_score = max(0, 100 - len(category_map["multiwan"]["issues"]) * 30 - len(category_map["multiwan"]["warnings"]) * 10)
    script_score = max(0, 100 - len(category_map["script"]["issues"]) * 30 - len(category_map["script"]["warnings"]) * 10)
    sec_score = max(0, 100 - len(category_map["security_ext"]["issues"]) * 30 - len(category_map["security_ext"]["warnings"]) * 10)

    # Caps validation checks
    # 1. Cap firewall score to 0 if firewall is completely empty
    firewall_score = sec_score
    if not model.firewall_rules:
        firewall_score = 0

    # 2. Cap security score to 40 if unsafe telnet/ftp services are enabled
    has_unsafe_services_enabled = any(s.name in ("telnet", "ftp") and not s.disabled for s in model.services)
    if has_unsafe_services_enabled:
        sec_score = min(40, sec_score)
        if firewall_score > 40:
            firewall_score = min(40, firewall_score)

    monitoring_score = max(0, 100 - len(category_map["monitoring"]["issues"]) * 30 - len(category_map["monitoring"]["warnings"]) * 10)

    category_map["l2"]["score"] = l2_score
    category_map["firewall"]["score"] = firewall_score
    category_map["security_ext"]["score"] = sec_score

    # Check blocking reasons for internet access
    has_masquerade = False
    for rule in model.firewall_nat:
        if rule.chain == "srcnat" and rule.action == "masquerade":
            has_masquerade = True

    has_default_route = False
    route_lines = model.raw_sections.get("/ip route", [])
    for line in route_lines:
        if "gateway=" in line and ("dst-address=0.0.0.0/0" in line or "dst-address=" not in line):
            has_default_route = True

    # Also check dhcp-client with add-default-route=yes (same as audit plugin l3)
    if not has_default_route:
        dhcp_client_lines = model.raw_sections.get("/ip dhcp-client", [])
        for line in dhcp_client_lines:
            from backend.parsers.base import get_param_value as _gpv
            add_default = _gpv(line, "add-default-route")
            disabled = _gpv(line, "disabled") == "yes"
            if not disabled and add_default != "no":
                has_default_route = True
                break

    if not has_masquerade:
        critical_failures.append("❌ NAT: Відсутнє правило srcnat masquerade — клієнти не матимуть Інтернету")
    if not has_default_route:
        critical_failures.append("❌ Відсутній дефолтний маршрут (0.0.0.0/0) — немає виходу в Інтернет")

    if critical_failures:
        readiness_score = 0
        verdict = "NOT READY FOR PRODUCTION"
    else:
        readiness_score = int(l2_score * 0.2 + vlan_score * 0.15 + dhcp_score * 0.15 + wifi_score * 0.15 + sec_score * 0.2 + routing_score * 0.15)
        verdict = "READY" if readiness_score >= 80 else "NOT READY FOR PRODUCTION"

    category_map["production_readiness"] = {
        "score": readiness_score,
        "verdict": verdict,
        "critical_failures": critical_failures,
        "breakdown": {
            "l2": l2_score,
            "vlan": vlan_score,
            "dhcp": dhcp_score,
            "wifi": wifi_score,
            "capsman": wifi_score,
            "firewall": sec_score,
            "routing": routing_score,
            "multiwan": multiwan_score,
            "script": script_score,
            "security": sec_score,
            "monitoring": monitoring_score
        }
    }

    # 6. Overall summary
    category_map["summary"] = {
        "score": readiness_score,
        "total_issues": all_issues,
        "total_warnings": all_warnings
    }

    # 7. Deduplicate findings across categories
    dedup_keys = ["l2", "vlan", "vlan_ext", "dhcp", "dhcp_ext", "wifi", "wifi_ext",
                  "capsman", "capsman_ext", "security", "security_ext", "firewall",
                  "performance", "performance_ext", "routing", "multiwan",
                  "script", "monitoring", "backup", "services", "orphan_objects"]
    for key in dedup_keys:
        if key in category_map and isinstance(category_map[key], dict):
            for field in ["issues", "warnings", "fixes", "info"]:
                if field in category_map[key]:
                    # Preserve order, remove duplicates
                    seen = set()
                    unique = []
                    for item in category_map[key][field]:
                        if item not in seen:
                            seen.add(item)
                            unique.append(item)
                    category_map[key][field] = unique

    return category_map
