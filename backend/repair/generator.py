import copy
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.models.network_model import NetworkModel, ConfigGenRequest
from backend.parsers.network_model import parse_to_model
from backend.audit.base import registry
from backend.dependency.graph import sort_fixes
from backend.repair.diff import generate_config_diff
from backend.repair.rollback import generate_rollback_instructions
from backend.audit.compliance import audit_compliance

def get_device_profile(device_type: str) -> dict:
    device_type = device_type.lower()
    if "hap-ax3" in device_type or "hap_ax3" in device_type:
        return {
            "is_router": True,
            "ports": ["ether1", "ether2", "ether3", "ether4", "ether5"],
            "wan_interface": "ether1",
            "lan_ports": ["ether2", "ether3", "ether4", "ether5"],
            "trunk_ports": ["ether5"],
            "access_ports": ["ether2", "ether3", "ether4"],
            "wireless_ports": ["wifi1", "wifi2"]
        }
    elif "cap-ax" in device_type or "cap_ax" in device_type:
        return {
            "is_router": False,
            "ports": ["ether1", "ether2"],
            "wan_interface": None,
            "lan_ports": ["ether1", "ether2"],
            "trunk_ports": ["ether1"],
            "access_ports": ["ether2"],
            "wireless_ports": ["wifi1", "wifi2"]
        }
    elif "rb4011" in device_type:
        return {
            "is_router": True,
            "ports": [f"ether{i}" for i in range(1, 11)],
            "wan_interface": "ether1",
            "lan_ports": [f"ether{i}" for i in range(2, 11)],
            "trunk_ports": ["ether10"],
            "access_ports": [f"ether{i}" for i in range(2, 10)],
            "wireless_ports": []
        }
    elif "chr" in device_type:
        return {
            "is_router": True,
            "ports": ["ether1", "ether2"],
            "wan_interface": "ether1",
            "lan_ports": ["ether2"],
            "trunk_ports": [],
            "access_ports": ["ether2"],
            "wireless_ports": []
        }
    else:
        return {
            "is_router": True,
            "ports": ["ether1", "ether2"],
            "wan_interface": "ether1",
            "lan_ports": ["ether2"],
            "trunk_ports": [],
            "access_ports": ["ether2"],
            "wireless_ports": []
        }

def get_wifi_section(ros_version: str) -> str:
    if "7.12" in ros_version or "7.13" in ros_version:
        return "wifiwave2"
    return "wifi"

def generate_config(req: ConfigGenRequest, compliance_profile: str = "basic") -> str:
    profile = get_device_profile(req.device_type)
    wifi_section = get_wifi_section(req.ros_version)

    lines = []
    lines.append("##HEADER_PLACEHOLDER##")
    lines.append(f"# Device: {req.device_type} | Profile: {compliance_profile.upper()} | Country: {req.country} | ROS Version: {req.ros_version}")
    lines.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")

    # System Identity
    lines.append("/system identity")
    lines.append(f"set name=\"Router-{req.device_type.upper()}\"")
    lines.append("")

    # Interface lists
    lines.append("/interface list")
    lines.append("add name=WAN comment=\"WAN list\"")
    lines.append("add name=LAN comment=\"LAN list\"")
    lines.append("")

    lines.append("/interface list member")
    if profile["is_router"] and profile["wan_interface"]:
        lines.append(f"add interface={profile['wan_interface']} list=WAN")
    lines.append("add interface=bridge list=LAN")
    lines.append("")

    # DNS configuration
    dns_servers = "1.1.1.1,1.0.0.1"
    if req.dns_mode == "google":
        dns_servers = "8.8.8.8,8.8.4.4"
    elif req.dns_mode == "quad9":
        dns_servers = "9.9.9.9,149.112.112.112"
    elif req.dns_mode == "custom":
        dns_servers = req.dns_custom or "1.1.1.1"

    # NTP
    ntp_primary = "0.pool.ntp.org"
    ntp_secondary = "1.pool.ntp.org"
    if req.ntp_mode == "google":
        ntp_primary = "time.google.com"
        ntp_secondary = ""
    elif req.ntp_mode == "custom" and req.ntp_custom:
        parts = [p.strip() for p in req.ntp_custom.split(",") if p.strip()]
        if len(parts) > 0: ntp_primary = parts[0]
        if len(parts) > 1: ntp_secondary = parts[1]

    # Bridge
    lines.append("/interface bridge")
    lines.append("add name=bridge vlan-filtering=yes fast-forward=no comment=\"Main Local Bridge\"")
    lines.append("")

    # VLANs
    if req.vlans:
        lines.append("# VLAN Interfaces")
        for vlan in req.vlans:
            vid = vlan.get("id", 10)
            name = vlan.get("name", f"vlan{vid}")
            lines.append(f"/interface vlan")
            lines.append(f"add interface=bridge name={name} vlan-id={vid}")
        lines.append("")

        # Bridge ports
        lines.append("# Bridge Port Mapping")
        lines.append("/interface bridge port")

        for idx, vlan in enumerate(req.vlans):
            vid = vlan.get("id", 10)
            if idx < len(profile["access_ports"]):
                port = profile["access_ports"][idx]
                lines.append(f"add bridge=bridge interface={port} pvid={vid} comment=\"Access VLAN {vid}\"")

        for t_port in profile["trunk_ports"]:
            lines.append(f"add bridge=bridge interface={t_port} comment=\"Trunk Port\"")

        if not req.capsman and profile["wireless_ports"]:
            for w_port in profile["wireless_ports"]:
                lines.append(f"add bridge=bridge interface={w_port} comment=\"WiFi Interface (Auto-VLAN)\"")
        lines.append("")

        # Bridge VLAN Table
        lines.append("# Bridge VLAN Table Configuration")
        lines.append("/interface bridge vlan")
        for idx, vlan in enumerate(req.vlans):
            vid = vlan.get("id", 10)
            name = vlan.get("name", f"vlan{vid}")

            tagged_ports = ["bridge"] + profile["trunk_ports"]
            untagged_ports = []
            if idx < len(profile["access_ports"]):
                untagged_ports.append(profile["access_ports"][idx])

            if not req.capsman:
                for ssid in req.ssids:
                    if ssid.get("vlan") == vid:
                        for w_port in profile["wireless_ports"]:
                            tagged_ports.append(w_port)

            tagged_str = ",".join(list(set(tagged_ports)))
            untagged_str = f" untagged={','.join(untagged_ports)}" if untagged_ports else ""
            lines.append(f"add bridge=bridge tagged={tagged_str}{untagged_str} vlan-ids={vid} comment=\"VLAN {vid} - {name}\"")

        lines.append("")
        lines.append("# IP Addresses")
        lines.append("/ip address")
        for vlan in req.vlans:
            vid = vlan.get("id", 10)
            name = vlan.get("name", f"vlan{vid}")
            gw = vlan.get("gateway", f"10.{vid}.0.1")
            mask = vlan.get("mask", "24")
            lines.append(f"add address={gw}/{mask} interface={name} comment=\"GW for {name}\"")

        if profile["is_router"] and profile["wan_interface"]:
            lines.append("")
            lines.append("# WAN Interface DHCP Client")
            lines.append("/ip dhcp-client")
            lines.append(f"add interface={profile['wan_interface']} use-peer-dns=yes use-peer-ntp=yes add-default-route=yes disabled=no comment=\"WAN Connection\"")

        lines.append("")
        lines.append("# DHCP Pools & Servers")
        lines.append("/ip pool")
        for vlan in req.vlans:
            vid = vlan.get("id", 10)
            name = vlan.get("name", f"vlan{vid}")
            gw = vlan.get("gateway", f"10.{vid}.0.1")

            subnet_prefix = "10.10.0"
            gw_parts = gw.split(".")
            if len(gw_parts) == 4:
                subnet_prefix = ".".join(gw_parts[:3])

            start = vlan.get("dhcp_start", f"{subnet_prefix}.10")
            end = vlan.get("dhcp_end", f"{subnet_prefix}.254")
            lines.append(f"add name=pool_{name} ranges={start}-{end}")

        lines.append("/ip dhcp-server")
        for vlan in req.vlans:
            vid = vlan.get("id", 10)
            name = vlan.get("name", f"vlan{vid}")
            lines.append(f"add name=dhcp_{name} interface={name} address-pool=pool_{name} disabled=no lease-time=8h")

        lines.append("/ip dhcp-server network")
        for vlan in req.vlans:
            vid = vlan.get("id", 10)
            name = vlan.get("name", f"vlan{vid}")
            gw = vlan.get("gateway", f"10.{vid}.0.1")
            subnet_prefix = "10.10.0"
            gw_parts = gw.split(".")
            if len(gw_parts) == 4:
                subnet_prefix = ".".join(gw_parts[:3])

            dns_srv = dns_servers.split(",")[0] if dns_servers else gw
            lines.append(f"add address={subnet_prefix}.0/24 gateway={gw} dns-server={dns_srv} comment=\"Network for {name}\"")

    # WiFi / CAPsMAN
    if req.ssids:
        lines.append("")
        if req.capsman:
            lines.append(f"# RouterOS v7 CAPsMAN ({wifi_section}) Configuration")
            lines.append(f"/interface {wifi_section} capsman")
            lines.append("set enabled=yes require-peer-certificate=no")
            lines.append("")
            lines.append(f"/interface {wifi_section} security")
            lines.append(f"add name=sec_capsman_wpa23 authentication-types=wpa2-psk,wpa3-psk passphrase=\"{req.wifi_password}\"")
            lines.append("")
            lines.append(f"/interface {wifi_section} configuration")
            for ssid in req.ssids:
                ssid_name = ssid.get("name", "WiFi").lower().replace(" ", "_")
                ssid_str = ssid.get("name", "MyNetwork")
                vid = ssid.get("vlan", 10)
                lines.append(f"add name=cfg_{ssid_name} ssid=\"{ssid_str}\" security=sec_capsman_wpa23 \\")
                lines.append(f"    datapath.bridge=bridge datapath.vlan-id={vid} datapath.vlan-mode=use-tag country=\"{req.country}\"")
            lines.append("")
            lines.append(f"/interface {wifi_section} capsman provisioning")
            main_ssid_name = req.ssids[0].get("name", "WiFi").lower().replace(" ", "_")
            lines.append(f"add action=create-dynamic-enabled master-configuration=cfg_{main_ssid_name} supported-bands=2ghz,5ghz")
        else:
            lines.append(f"# RouterOS v7 Standalone WiFi ({wifi_section}) Configuration")
            lines.append(f"/interface {wifi_section} security")
            lines.append(f"add name=sec_local_wpa23 authentication-types=wpa2-psk,wpa3-psk passphrase=\"{req.wifi_password}\"")
            lines.append("")

            for ssid in req.ssids:
                ssid_name = ssid.get("name", "WiFi").lower().replace(" ", "_")
                ssid_str = ssid.get("name", "MyNetwork")
                vid = ssid.get("vlan", 10)
                lines.append(f"/interface {wifi_section} configuration")
                lines.append(f"add name=cfg_{ssid_name} ssid=\"{ssid_str}\" security=sec_local_wpa23 \\")
                lines.append(f"    datapath.vlan-id={vid} datapath.vlan-mode=use-tag country=\"{req.country}\"")
            lines.append("")

            lines.append("# Assign configurations to physical wifi interfaces")
            main_ssid = req.ssids[0]
            main_ssid_name = main_ssid.get("name", "WiFi").lower().replace(" ", "_")

            if profile["wireless_ports"]:
                for w_port in profile["wireless_ports"]:
                    lines.append(f"set [find where name~\"{w_port}\"] configuration=cfg_{main_ssid_name} disabled=no")

            if len(req.ssids) > 1:
                lines.append("")
                lines.append("# Secondary SSIDs (Virtual WiFi Interfaces)")
                for idx, ssid in enumerate(req.ssids[1:], start=1):
                    ssid_name = ssid.get("name", "WiFi").lower().replace(" ", "_")
                    lines.append(f"add name=wifi-virtual{idx} master-interface=wifi1 configuration=cfg_{ssid_name} disabled=no")

    # Firewall & Security Hardening based on profile
    if profile["is_router"]:
        lines.append("")
        lines.append(f"# Firewall & Security Hardening - Profile {compliance_profile.upper()}")
        lines.append("/ip firewall filter")

        # 1. ESTABLISHED/RELATED (High Priority)
        lines.append("add chain=input action=accept connection-state=established,related,untracked comment=\"Accept-Established-Input\"")
        lines.append("add chain=input action=drop connection-state=invalid comment=\"Drop-Invalid-Input\"")
        lines.append("add chain=input action=accept protocol=icmp comment=\"Accept-ICMP\"")

        # 2. Local Access rules
        if compliance_profile in ("secure", "hardened", "enterprise"):
            lines.append("add chain=input action=accept src-address-list=mgmt comment=\"Accept-Mgmt-Only\"")
        else:
            lines.append("add chain=input action=accept in-interface-list=LAN comment=\"Accept-Local-Bridge\"")

        # 3. Forward rules
        lines.append("add chain=forward action=fasttrack-connection connection-state=established,related hw-offload=yes comment=\"FastTrack\"")
        lines.append("add chain=forward action=accept connection-state=established,related,untracked comment=\"Accept-Forward\"")
        lines.append("add chain=forward action=drop connection-state=invalid comment=\"Drop-Invalid-Forward\"")
        lines.append("add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment=\"Allow LAN to WAN\"")

        # 4. Strict Blocking / Drops at bottom
        if compliance_profile in ("secure", "hardened", "enterprise"):
            # Drop incoming DNS requests from WAN to prevent open resolver issues
            lines.append("add chain=input action=drop protocol=udp dst-port=53 in-interface-list=WAN comment=\"Drop WAN DNS UDP\"")
            lines.append("add chain=input action=drop protocol=tcp dst-port=53 in-interface-list=WAN comment=\"Drop WAN DNS TCP\"")

            lines.append("add chain=forward action=drop comment=\"Drop-All-Other-Forward\"")
            lines.append("add chain=input action=drop comment=\"Drop-All-Other-Input\"")
        else:
            lines.append("add chain=input action=drop in-interface-list=WAN comment=\"Drop WAN Input\"")
            lines.append("add chain=forward action=drop connection-nat-state=!dstnat in-interface-list=WAN comment=\"Drop WAN Forward without DST-NAT\"")

        # Masquerade NAT
        lines.append("")
        lines.append("/ip firewall nat")
        lines.append("add chain=srcnat action=masquerade out-interface-list=WAN comment=\"Default masquerade WAN list\"")

    # IP DNS
    if dns_servers:
        lines.append("")
        lines.append("/ip dns")
        lines.append(f"set servers={dns_servers} allow-remote-requests=yes")

    # NTP Client
    if ntp_primary:
        lines.append("")
        lines.append("/system ntp client")
        sec_param = f" secondary-ntp={ntp_secondary}" if ntp_secondary else ""
        lines.append(f"set enabled=yes primary-ntp={ntp_primary}{sec_param}")

    # Security Hardening parameters
    lines.append("")
    lines.append("/ip service")
    lines.append("set telnet disabled=yes")
    lines.append("set ftp disabled=yes")

    if compliance_profile in ("hardened", "enterprise"):
        lines.append("set www disabled=yes")
        lines.append("set api disabled=yes")
        lines.append("set api-ssl disabled=yes")
        lines.append("set ssh port=22 disabled=no")
        lines.append("set winbox port=8291 address=192.168.0.0/16,10.0.0.0/8")
    else:
        lines.append("set www disabled=no")
        lines.append("set ssh port=22 disabled=no")
        lines.append("set winbox port=8291 disabled=no")

    lines.append("")
    lines.append("/ip ssh")
    lines.append("set strong-crypto=yes")
    lines.append("")

    # Discovery settings
    lines.append("/ip neighbor discovery-settings")
    if compliance_profile in ("hardened", "enterprise"):
        lines.append("set discover-interface-list=none")
    else:
        lines.append("set discover-interface-list=LAN")

    return "\n".join(lines)


def auto_repair_config(config_text: str, compliance_profile: str = "basic") -> dict:
    model = parse_to_model(config_text)

    # 1. Collect all fixes and errors by running dynamic Audit plugins
    all_fixes = []
    issues_list = []
    warnings_list = []
    info_list = []
    plugins_log = []

    for plugin in registry.get_plugins():
        res = plugin.run(model)

        # Explain Like Engineer metadata mapping
        explain_meta = {
            "id": plugin.id,
            "title": plugin.title,
            "severity": plugin.severity,
            "confidence": plugin.confidence,
            "description": plugin.description,
            "impact": plugin.impact,
            "best_practice": plugin.best_practice,
            "resolution": plugin.resolution,
            "fixes": res["fixes"]
        }
        plugins_log.append(explain_meta)

        all_fixes.extend(res["fixes"])
        issues_list.extend(res["issues"])
        warnings_list.extend(res["warnings"])
        info_list.extend(res["info"])

    # 2. Sort fixes using the ConfigDependencyGraph topologically
    sorted_remedy_commands = sort_fixes(all_fixes)

    # 3. Create REMEDIED ORIGINAL text config
    rollback_script = generate_rollback_instructions("pre_repair")
    remedy_text = rollback_script + "\n# BEGIN REMEDIATION\n"
    remedy_text += "\n".join(sorted_remedy_commands)
    remedy_text += "\n# END REMEDIATION\n"

    # We append the remediation blocks to the original text config (safer than trying to edit raw files line-by-line)
    remedied_original = config_text.rstrip() + "\n\n" + remedy_text

    # 4. Create CLEAN REFACTORED config from Model
    # Transform model details to ConfigGenRequest
    gen_vlans = []
    for v in model.vlans:
        # Find gateway IP from model.ips
        gw = f"10.{v.vlan_id}.0.1"
        for ip in model.ips:
            if ip.interface == v.name:
                gw = ip.address.split("/")[0]
                break
        gen_vlans.append({
            "id": v.vlan_id,
            "name": v.name,
            "gateway": gw
        })

    # Default LAN VLAN if model contains none
    if not gen_vlans:
        gen_vlans = [{"id": 10, "name": "LAN", "gateway": "10.10.0.1"}]

    gen_ssids = []
    for w in model.wifi:
        gen_ssids.append({
            "name": w.ssid,
            "vlan": w.vlan_id or gen_vlans[0]["id"]
        })

    if not gen_ssids:
        gen_ssids = [{"name": "MikroTik-WiFi", "vlan": gen_vlans[0]["id"]}]

    req = ConfigGenRequest(
        device_type=model.hardware,
        ros_version=model.version,
        vlans=gen_vlans,
        ssids=gen_ssids,
        country="Ukraine",
        capsman=len(model.wifi) > 3, # Guess capsman if multiple wifi interfaces exist
        wifi_password="SecureWiFi123!",
        dns_mode="custom" if model.dns_servers else "cloudflare",
        dns_custom=",".join(model.dns_servers) if model.dns_servers else "",
        ntp_mode="custom" if model.ntp_servers else "pool",
        ntp_custom=",".join(model.ntp_servers) if model.ntp_servers else "",
        firewall_profile="strict" if compliance_profile in ("secure", "hardened", "enterprise") else "basic"
    )

    refactored_clean = generate_config(req, compliance_profile)

    # Prepend dynamic production readiness card details to refactored config
    final_score = 100 - len(issues_list)*15 - len(warnings_list)*5
    final_score = max(0, min(100, final_score))

    header = []
    header.append("# ===========================================================")
    header.append("# PROFESSIONAL MIKROTIK ROUTEROS V7 CONFIGURATION")
    header.append(f"# Refactored Compliance Profile: {compliance_profile.upper()}")
    header.append(f"# Est. Production Readiness:    {final_score}%")
    header.append("# ===========================================================")
    header.append("")
    refactored_clean = refactored_clean.replace("##HEADER_PLACEHOLDER##", "\n".join(header))

    # 5. Diff snapshot generator
    config_diff = generate_config_diff(config_text, remedied_original)

    # 6. Change Impact Analysis
    impact_analysis = []
    for cmd in sorted_remedy_commands:
        if "vlan-filtering=yes" in cmd:
            impact_analysis.append("⚠️ Увімкнення vlan-filtering на мікротику тимчасово розірве зв'язок на всіх портах мосту (до 5-10 секунд).")
        if "port set" in cmd or "port add" in cmd:
            impact_analysis.append("⚠️ Додавання або зміна PVID на портах мосту призведе до зміни VLAN сегментів підключених девайсів та оновлення їх DHCP лізів.")
        if "disable" in cmd and ("winbox" in cmd or "ssh" in cmd or "www" in cmd):
            impact_analysis.append(f"⚠️ Вимкнення керуючого сервісу ({cmd}) обмежить шляхи адміністрування пристрою.")

    # Remove duplicates in impact logs
    impact_analysis = list(set(impact_analysis))
    if not impact_analysis:
        impact_analysis.append("✅ Застосування виправлень безпечне. Переривання сервісів або втрата доступу малоймовірні.")

    # 7. Complexity Score
    vlans_cnt = len(model.vlans)
    wifi_cnt = len(model.wifi)
    dhcp_cnt = len(model.dhcp_servers)
    firewall_cnt = len(model.firewall_rules) + len(model.firewall_nat)

    complexity_val = min(100, (vlans_cnt * 5) + (wifi_cnt * 5) + (dhcp_cnt * 6) + (firewall_cnt * 1.5))
    complexity_val = int(max(10, complexity_val))

    if complexity_val >= 80:
        complexity_desc = "Дуже складна (Enterprise / Core Router)"
    elif complexity_val >= 45:
        complexity_desc = "Середня (Branch Office / SMB)"
    else:
        complexity_desc = "Проста (Home / Small Office)"

    complexity = {
        "score": complexity_val,
        "description": complexity_desc,
        "vlans": vlans_cnt,
        "ssids": wifi_cnt,
        "dhcp_servers": dhcp_cnt,
        "firewall_rules": firewall_cnt
    }

    # 8. Dry Run Validation on remedied original
    remedied_model = parse_to_model(remedied_original)
    dry_run_issues = []
    for plugin in registry.get_plugins():
        res = plugin.run(remedied_model)
        dry_run_issues.extend(res["issues"])

    dry_run_status = "SUCCESS" if not dry_run_issues else "WARNING"

    return {
        "remedied_original": remedied_original,
        "refactored_clean": refactored_clean,
        "diff": config_diff,
        "impact_analysis": impact_analysis,
        "complexity": complexity,
        "dry_run": {
            "status": dry_run_status,
            "remaining_issues": dry_run_issues
        },
        "plugins_log": plugins_log
    }
