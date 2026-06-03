import re
from typing import Dict, Any, List
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value, get_section

def audit_compliance(model: NetworkModel, policy: dict) -> dict:
    violations = []
    passed = []

    # 1. IP Services
    disabled_services = policy.get("disabled_services", [])
    for svc in disabled_services:
        srv_obj = next((s for s in model.services if s.name == svc), None)
        # If not declared in model services, it defaults to enabled in RouterOS unless disabled=yes is explicit.
        # But our parser populates model.services from /ip service. If a service isn't listed, it might be enabled.
        # So we check if there is an explicit service model that says disabled=True.
        is_disabled = srv_obj.disabled if srv_obj else False
        if not is_disabled:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: сервіс '{svc}' має бути вимкнений",
                "fix": f"/ip service disable {svc}"
            })
        else:
            passed.append(f"Сервіс '{svc}' вимкнено ✓")

    # Winbox Port
    winbox_port = policy.get("winbox_port")
    if winbox_port:
        winbox_srv = next((s for s in model.services if s.name == "winbox"), None)
        current_port = winbox_srv.port if winbox_srv else 8291
        if current_port != winbox_port:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: Winbox порт має бути {winbox_port} (поточний: {current_port})",
                "fix": f"/ip service set winbox port={winbox_port}"
            })
        else:
            passed.append(f"Winbox порт={winbox_port} ✓")

    # Winbox allowed addresses
    winbox_addresses = policy.get("winbox_allowed_addresses", "")
    if winbox_addresses:
        winbox_srv = next((s for s in model.services if s.name == "winbox"), None)
        addr_val = winbox_srv.address if winbox_srv else None
        if not addr_val:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: Winbox має бути обмежений по IP ({winbox_addresses})",
                "fix": f"/ip service set winbox address=\"{winbox_addresses}\""
            })
        elif addr_val != winbox_addresses:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: Winbox дозволені IP мають бути '{winbox_addresses}' (поточні: '{addr_val}')",
                "fix": f"/ip service set winbox address=\"{winbox_addresses}\""
            })
        else:
            passed.append("Winbox обмежений правильними IP ✓")

    # SSH Port
    ssh_port = policy.get("ssh_port")
    if ssh_port:
        ssh_srv = next((s for s in model.services if s.name == "ssh"), None)
        current_port = ssh_srv.port if ssh_srv else 22
        if current_port != ssh_port:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: SSH порт має бути {ssh_port} (поточний: {current_port})",
                "fix": f"/ip service set ssh port={ssh_port}"
            })
        else:
            passed.append(f"SSH порт={ssh_port} ✓")

    # SSH allowed addresses
    ssh_addresses = policy.get("ssh_allowed_addresses", "")
    if ssh_addresses:
        ssh_srv = next((s for s in model.services if s.name == "ssh"), None)
        addr_val = ssh_srv.address if ssh_srv else None
        if not addr_val:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: SSH має бути обмежений по IP ({ssh_addresses})",
                "fix": f"/ip service set ssh address=\"{ssh_addresses}\""
            })
        elif addr_val != ssh_addresses:
            violations.append({
                "type": "compliance",
                "section": "IP Services",
                "message": f"Регламент: SSH дозволені IP мають бути '{ssh_addresses}' (поточні: '{addr_val}')",
                "fix": f"/ip service set ssh address=\"{ssh_addresses}\""
            })
        else:
            passed.append("SSH обмежений правильними IP ✓")

    # 2. IPv6
    if policy.get("disable_ipv6"):
        # Look for IPv6 address presence or non-disabled IPv6 settings in raw sections
        ipv6_addr_present = any("ipv6" in k.lower() for k in model.raw_sections.keys() if "address" in k.lower())
        ipv6_settings = get_section(model.raw_sections, "/ipv6 settings")
        disable_ipv6_val = any("disable-ipv6=yes" in l for l in ipv6_settings)

        if ipv6_addr_present and not disable_ipv6_val:
            violations.append({
                "type": "compliance",
                "section": "IPv6",
                "message": "Регламент: IPv6 має бути вимкнений",
                "fix": "/ipv6 settings set disable-ipv6=yes\n/ipv6 address remove [find]"
            })
        else:
            passed.append("IPv6 вимкнено ✓")

    # 3. Identity
    identity_prefix = policy.get("identity_prefix", "")
    identity_regex = policy.get("identity_regex", "")
    if identity_prefix or identity_regex:
        identity_lines = get_section(model.raw_sections, "/system identity")
        identity_name = ""
        for l in identity_lines:
            val = get_param_value(l, "name")
            if val:
                identity_name = val

        if not identity_name:
            violations.append({
                "type": "compliance",
                "section": "System Identity",
                "message": "Регламент: Identity не встановлено",
                "fix": f"/system identity set name=\"{policy.get('identity_example', identity_prefix + 'HOSTNAME')}\""
            })
        elif identity_prefix and not identity_name.startswith(identity_prefix):
            violations.append({
                "type": "compliance",
                "section": "System Identity",
                "message": f"Регламент: Identity має починатися з '{identity_prefix}' (поточне: '{identity_name}')",
                "fix": f"/system identity set name=\"{identity_prefix}{identity_name}\""
            })
        elif identity_regex:
            try:
                if not re.match(identity_regex, identity_name):
                    violations.append({
                        "type": "compliance",
                        "section": "System Identity",
                        "message": f"Регламент: Identity '{identity_name}' не відповідає шаблону '{identity_regex}'",
                        "fix": f"/system identity set name=\"{policy.get('identity_example', 'CORRECT-NAME')}\""
                    })
                else:
                    passed.append(f"Identity '{identity_name}' відповідає регламенту ✓")
            except: pass
        else:
            passed.append(f"Identity '{identity_name}' відповідає регламенту ✓")

    # 4. Syslog
    if policy.get("syslog_enabled") and policy.get("syslog_host"):
        syslog_host = policy["syslog_host"]
        if not model.syslog_enabled or model.syslog_host != syslog_host:
            port = policy.get("syslog_port", 514)
            topics = policy.get("syslog_topics", "!debug,!packet")
            violations.append({
                "type": "compliance",
                "section": "Logging",
                "message": f"Регламент: відсутнє логування на Graylog/Syslog ({syslog_host})",
                "fix": f"/system logging action add name=graylog target=remote remote={syslog_host} remote-port={port}\n/system logging add action=graylog topics={topics}"
            })
        else:
            passed.append(f"Syslog/Graylog логування налаштовано ✓")

    # 5. SSH Strong Crypto
    if policy.get("ssh_strong_crypto"):
        ssh_lines = get_section(model.raw_sections, "/ip ssh")
        if ssh_lines and not any("strong-crypto=yes" in l for l in ssh_lines):
            violations.append({
                "type": "compliance",
                "section": "SSH",
                "message": "Регламент: SSH має використовувати strong-crypto=yes",
                "fix": "/ip ssh set strong-crypto=yes"
            })
        else:
            passed.append("SSH strong-crypto увімкнено ✓")

    # 6. NTP
    ntp_primary = policy.get("ntp_primary", "")
    if ntp_primary:
        has_ntp = any(ntp_primary in s for s in model.ntp_servers)
        if not has_ntp:
            ntp2 = policy.get("ntp_secondary", "")
            violations.append({
                "type": "compliance",
                "section": "NTP",
                "message": f"Регламент: NTP сервер має бути {ntp_primary}",
                "fix": f"/system ntp client set enabled=yes primary-ntp={ntp_primary}" + (f" secondary-ntp={ntp2}" if ntp2 else "")
            })
        else:
            passed.append(f"NTP сервер {ntp_primary} налаштовано ✓")

    # 7. DNS
    dns_servers = policy.get("dns_servers", "")
    if dns_servers:
        first_dns = dns_servers.split(",")[0].strip()
        has_dns = any(first_dns in s for s in model.dns_servers)
        if not has_dns:
            violations.append({
                "type": "compliance",
                "section": "DNS",
                "message": f"Регламент: DNS сервери мають бути {dns_servers}",
                "fix": f"/ip dns set servers={dns_servers}"
            })
        else:
            passed.append(f"DNS сервери налаштовано ✓")

    # 8. Custom rules
    for rule in policy.get("custom_rules", []):
        section_key = rule.get("section", "")
        must_contain = rule.get("must_contain", "")
        description = rule.get("description", "")
        fix = rule.get("fix", "")
        if section_key and must_contain:
            section_lines = get_section(model.raw_sections, section_key)
            all_text = "\n".join(section_lines)
            if must_contain not in all_text:
                violations.append({
                    "type": "compliance",
                    "section": "Спеціальне правило",
                    "message": f"Регламент: {description or must_contain}",
                    "fix": fix
                })
            else:
                passed.append(f"Правило '{description or must_contain}' виконано ✓")

    return {
        "violations": violations,
        "passed": passed,
        "compliant": len(violations) == 0,
        "score": max(0, 100 - len(violations) * 20) if (violations or passed) else None
    }

def apply_policy_to_config(lines: List[str], policy: dict) -> List[str]:
    extra = ["", "# ─── Регламент компанії ─────────────────────────────────────"]

    disabled = policy.get("disabled_services", [])
    winbox_port = policy.get("winbox_port", 8291)
    ssh_port = policy.get("ssh_port", 22)
    winbox_addr = policy.get("winbox_allowed_addresses", "")
    ssh_addr = policy.get("ssh_allowed_addresses", "")

    if disabled or winbox_port or ssh_port:
        extra.append("/ip service")
        for svc in disabled:
            extra.append(f"disable {svc}")
        if winbox_port:
            addr_part = f" address={winbox_addr}" if winbox_addr else ""
            extra.append(f"set winbox port={winbox_port}{addr_part} disabled=no")
        if ssh_port:
            addr_part = f" address={ssh_addr}" if ssh_addr else ""
            extra.append(f"set ssh port={ssh_port}{addr_part} disabled=no")

    if policy.get("ssh_strong_crypto"):
        extra.append("/ip ssh")
        extra.append("set strong-crypto=yes")

    if policy.get("disable_ipv6"):
        extra.append("/ipv6 settings")
        extra.append("set disable-ipv6=yes")

    identity_example = policy.get("identity_example", "")
    if identity_example:
        extra.append("/system identity")
        extra.append(f"set name=\"{identity_example}\"")

    if policy.get("syslog_enabled") and policy.get("syslog_host"):
        host = policy["syslog_host"]
        port = policy.get("syslog_port", 514)
        topics = policy.get("syslog_topics", "!debug,!packet")
        extra.append("/system logging action")
        extra.append(f"add name=graylog target=remote remote={host} remote-port={port} bsd-syslog=yes syslog-facility=local0")
        extra.append("/system logging")
        extra.append(f"add action=graylog topics={topics}")

    ntp_primary = policy.get("ntp_primary", "")
    ntp_secondary = policy.get("ntp_secondary", "")
    if ntp_primary:
        extra.append("/system ntp client")
        sec = f" secondary-ntp={ntp_secondary}" if ntp_secondary else ""
        extra.append(f"set enabled=yes primary-ntp={ntp_primary}{sec}")

    dns_servers = policy.get("dns_servers", "")
    if dns_servers:
        extra.append("/ip dns")
        extra.append(f"set servers={dns_servers} allow-remote-requests=yes")

    for rule in policy.get("custom_rules", []):
        if rule.get("fix"):
            extra.append(f"# {rule.get('description','Custom rule')}")
            extra.append(rule["fix"])

    return lines + extra
