# -*- coding: utf-8 -*-
"""
MikroTik Configuration Cloner / Migrator
Remaps IP allocations and subnets from one network base to another.
"""
import re
import ipaddress

def clone_site_config(config_text: str, src_base: str, dst_base: str) -> str:
    """
    Parses configuration text and translates any IP references
    falling within 'src_base' into the corresponding offsets in 'dst_base'.
    """
    try:
        src_net = ipaddress.ip_network(src_base.strip(), strict=False)
        dst_net = ipaddress.ip_network(dst_base.strip(), strict=False)
    except Exception as e:
        raise ValueError(f"Невірний формат підмережі: {e}")

    # Regex to find subnets with mask (e.g., 10.10.0.0/16 or 192.168.88.0/24)
    # and single IP addresses (e.g. 10.10.20.1)
    # The regex checks for IP-like strings, optionally with CIDR mask.
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b')

    def remap_match(match):
        match_str = match.group(0)

        if '/' in match_str:
            # Subnet representation, e.g. 10.10.20.0/24
            addr, mask = match_str.split('/')
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj in src_net:
                    offset = int(ip_obj) - int(src_net.network_address)
                    new_ip = ipaddress.ip_address(int(dst_net.network_address) + offset)
                    return f"{new_ip}/{mask}"
            except Exception:
                pass
        else:
            # Single IP or part of a range
            try:
                ip_obj = ipaddress.ip_address(match_str)
                if ip_obj in src_net:
                    offset = int(ip_obj) - int(src_net.network_address)
                    new_ip = ipaddress.ip_address(int(dst_net.network_address) + offset)
                    return str(new_ip)
            except Exception:
                pass

        return match_str

    # Process replacement
    lines = config_text.splitlines()
    new_lines = []

    for line in lines:
        # Ignore comments to prevent changing informational notes or original header records
        if line.strip().startswith('#'):
            new_lines.append(line)
            continue

        new_line = ip_pattern.sub(remap_match, line)

        # Modify comments or identity references if needed, but here we do plain text swap
        new_lines.append(new_line)

    return "\n".join(new_lines)
