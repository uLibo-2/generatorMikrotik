import re
from typing import List, Dict, Any, Optional
from backend.models.network_model import (
    NetworkModel, InterfaceModel, BridgeModel, BridgePortModel, BridgeVlanModel,
    VlanInterfaceModel, IPAddressModel, DHCPPoolModel, DHCPServerModel,
    DHCPNetworkModel, DHCPStaticLease, WifiInterfaceModel, FirewallRuleModel,
    RouterOSService
)
from backend.parsers.base import (
    clean_comment_and_join_lines, get_param_value, get_section,
    detect_routeros_version, detect_hardware
)

def parse_to_model(config_text: str) -> NetworkModel:
    sections = clean_comment_and_join_lines(config_text)
    version_info = detect_routeros_version(config_text)
    hardware = detect_hardware(config_text)

    model = NetworkModel(
        version=version_info["version"],
        major_version=version_info["major"],
        hardware=hardware,
        raw_sections=sections
    )

    # 1. Parse Interfaces
    iface_sec = get_section(sections, "/interface")
    for line in iface_sec:
        name = get_param_value(line, "name")
        iface_type = get_param_value(line, "type") or "ethernet"
        disabled = get_param_value(line, "disabled") == "yes"
        comment = get_param_value(line, "comment")
        if name:
            model.interfaces.append(InterfaceModel(
                name=name, type=iface_type, disabled=disabled, comment=comment
            ))

    # 2. Parse Bridges
    bridge_sec = get_section(sections, "/interface bridge")
    bridge_map = {}
    for line in bridge_sec:
        name = get_param_value(line, "name")
        vlan_filtering = get_param_value(line, "vlan-filtering") == "yes"
        if name:
            bm = BridgeModel(name=name, vlan_filtering=vlan_filtering, ports=[], vlans=[])
            model.bridges.append(bm)
            bridge_map[name] = bm

    # Bridge Ports
    port_sec = get_section(sections, "/interface bridge port")
    for line in port_sec:
        iface = get_param_value(line, "interface")
        bridge_name = get_param_value(line, "bridge")
        pvid_str = get_param_value(line, "pvid")
        pvid = int(pvid_str) if (pvid_str and pvid_str.isdigit()) else 1
        hw = get_param_value(line, "hw") != "no"
        frame_types = get_param_value(line, "frame-types")
        ingress_filtering = get_param_value(line, "ingress-filtering") == "yes"
        edge = get_param_value(line, "edge")

        if iface and bridge_name in bridge_map:
            port_model = BridgePortModel(
                interface=iface, bridge=bridge_name, pvid=pvid, hw=hw,
                frame_types=frame_types, ingress_filtering=ingress_filtering, edge=edge
            )
            bridge_map[bridge_name].ports.append(port_model)

    # Bridge VLANs
    bvlan_sec = get_section(sections, "/interface bridge vlan")
    for line in bvlan_sec:
        bridge_name = get_param_value(line, "bridge")
        vids_str = get_param_value(line, "vlan-ids")
        tagged_str = get_param_value(line, "tagged")
        untagged_str = get_param_value(line, "untagged")

        if vids_str and bridge_name in bridge_map:
            vids = []
            for part in vids_str.split(","):
                if "-" in part:
                    try:
                        start, end = map(int, part.split("-"))
                        vids.extend(range(start, end + 1))
                    except: pass
                else:
                    try: vids.append(int(part))
                    except: pass

            tagged = [i.strip() for i in tagged_str.split(",") if i.strip()] if tagged_str else []
            untagged = [i.strip() for i in untagged_str.split(",") if i.strip()] if untagged_str else []

            vlan_model = BridgeVlanModel(
                bridge=bridge_name, vlan_ids=vids, tagged=tagged, untagged=untagged
            )
            bridge_map[bridge_name].vlans.append(vlan_model)

    # 3. Parse VLAN Interfaces
    vlan_sec = get_section(sections, "/interface vlan")
    for line in vlan_sec:
        name = get_param_value(line, "name")
        vlan_id_str = get_param_value(line, "vlan-id")
        iface = get_param_value(line, "interface")
        if name and vlan_id_str and vlan_id_str.isdigit() and iface:
            model.vlans.append(VlanInterfaceModel(
                name=name, vlan_id=int(vlan_id_str), interface=iface
            ))

    # 4. Parse IP Addresses
    ip_sec = get_section(sections, "/ip address")
    for line in ip_sec:
        addr = get_param_value(line, "address")
        iface = get_param_value(line, "interface")
        network = get_param_value(line, "network")
        if addr and iface:
            model.ips.append(IPAddressModel(address=addr, interface=iface, network=network))

    # 5. Parse DHCP Configuration
    pool_sec = get_section(sections, "/ip pool")
    for line in pool_sec:
        name = get_param_value(line, "name")
        ranges_str = get_param_value(line, "ranges")
        if name and ranges_str:
            ranges = [r.strip() for r in ranges_str.split(",")]
            model.dhcp_pools.append(DHCPPoolModel(name=name, ranges=ranges))

    dhcp_sec = get_section(sections, "/ip dhcp-server")
    for line in dhcp_sec:
        name = get_param_value(line, "name")
        iface = get_param_value(line, "interface")
        pool = get_param_value(line, "address-pool")
        disabled = get_param_value(line, "disabled") == "yes"
        lease_time = get_param_value(line, "lease-time")
        if name and iface and pool:
            model.dhcp_servers.append(DHCPServerModel(
                name=name, interface=iface, address_pool=pool, disabled=disabled, lease_time=lease_time
            ))

    net_sec = get_section(sections, "/ip dhcp-server network")
    for line in net_sec:
        addr = get_param_value(line, "address")
        gateway = get_param_value(line, "gateway")
        dns = get_param_value(line, "dns-server")
        if addr and gateway:
            model.dhcp_networks.append(DHCPNetworkModel(address=addr, gateway=gateway, dns_server=dns))

    lease_sec = get_section(sections, "/ip dhcp-server lease")
    for line in lease_sec:
        mac = get_param_value(line, "mac-address")
        addr = get_param_value(line, "address")
        comment = get_param_value(line, "comment")
        if mac and addr:
            model.dhcp_static_leases.append(DHCPStaticLease(mac_address=mac, address=addr, comment=comment))

    # 6. Parse WiFi Configuration (v6 and v7 compatibility)
    # v7 wifi
    wifi_sec = get_section(sections, "/interface wifi") or get_section(sections, "/interface wifiwave2")
    for line in wifi_sec:
        name = get_param_value(line, "name")
        ssid = get_param_value(line, "ssid") or name or "MikroTik-WiFi"
        sec_profile = get_param_value(line, "security")
        master = get_param_value(line, "master-interface")
        vlan_id_str = get_param_value(line, "datapath.vlan-id") or get_param_value(line, "vlan-id")
        vlan_id = int(vlan_id_str) if (vlan_id_str and vlan_id_str.isdigit()) else None
        disabled = get_param_value(line, "disabled") == "yes"
        if name:
            model.wifi.append(WifiInterfaceModel(
                name=name, ssid=ssid, security_profile=sec_profile,
                master_interface=master, vlan_id=vlan_id, disabled=disabled
            ))

    # v6 wireless
    wireless_sec = get_section(sections, "/interface wireless")
    for line in wireless_sec:
        name = get_param_value(line, "name")
        ssid = get_param_value(line, "ssid") or "MikroTik-Wireless"
        sec_profile = get_param_value(line, "security-profile")
        master = get_param_value(line, "master-interface")
        vlan_id_str = get_param_value(line, "vlan-id")
        vlan_id = int(vlan_id_str) if (vlan_id_str and vlan_id_str.isdigit()) else None
        disabled = get_param_value(line, "disabled") == "yes"
        if name:
            model.wifi.append(WifiInterfaceModel(
                name=name, ssid=ssid, security_profile=sec_profile,
                master_interface=master, vlan_id=vlan_id, disabled=disabled
            ))

    # 7. Parse Firewall
    filter_sec = get_section(sections, "/ip firewall filter")
    for line in filter_sec:
        chain = get_param_value(line, "chain")
        action = get_param_value(line, "action")
        if chain and action:
            model.firewall_rules.append(FirewallRuleModel(
                chain=chain, action=action,
                disabled=get_param_value(line, "disabled") == "yes",
                src_address=get_param_value(line, "src-address"),
                dst_address=get_param_value(line, "dst-address"),
                src_address_list=get_param_value(line, "src-address-list"),
                dst_address_list=get_param_value(line, "dst-address-list"),
                in_interface=get_param_value(line, "in-interface"),
                out_interface=get_param_value(line, "out-interface"),
                in_interface_list=get_param_value(line, "in-interface-list"),
                out_interface_list=get_param_value(line, "out-interface-list"),
                protocol=get_param_value(line, "protocol"),
                dst_port=get_param_value(line, "dst-port"),
                connection_state=get_param_value(line, "connection-state"),
                comment=get_param_value(line, "comment"),
                line=line
            ))

    nat_sec = get_section(sections, "/ip firewall nat")
    for line in nat_sec:
        chain = get_param_value(line, "chain")
        action = get_param_value(line, "action")
        if chain and action:
            model.firewall_nat.append(FirewallRuleModel(
                chain=chain, action=action,
                disabled=get_param_value(line, "disabled") == "yes",
                src_address=get_param_value(line, "src-address"),
                dst_address=get_param_value(line, "dst-address"),
                src_address_list=get_param_value(line, "src-address-list"),
                dst_address_list=get_param_value(line, "dst-address-list"),
                in_interface=get_param_value(line, "in-interface"),
                out_interface=get_param_value(line, "out-interface"),
                in_interface_list=get_param_value(line, "in-interface-list"),
                out_interface_list=get_param_value(line, "out-interface-list"),
                protocol=get_param_value(line, "protocol"),
                dst_port=get_param_value(line, "dst-port"),
                connection_state=get_param_value(line, "connection-state"),
                comment=get_param_value(line, "comment"),
                line=line
            ))

    mangle_sec = get_section(sections, "/ip firewall mangle")
    for line in mangle_sec:
        chain = get_param_value(line, "chain")
        action = get_param_value(line, "action")
        if chain and action:
            model.firewall_mangle.append(FirewallRuleModel(
                chain=chain, action=action,
                disabled=get_param_value(line, "disabled") == "yes",
                src_address=get_param_value(line, "src-address"),
                dst_address=get_param_value(line, "dst-address"),
                src_address_list=get_param_value(line, "src-address-list"),
                dst_address_list=get_param_value(line, "dst-address-list"),
                in_interface=get_param_value(line, "in-interface"),
                out_interface=get_param_value(line, "out-interface"),
                in_interface_list=get_param_value(line, "in-interface-list"),
                out_interface_list=get_param_value(line, "out-interface-list"),
                protocol=get_param_value(line, "protocol"),
                dst_port=get_param_value(line, "dst-port"),
                connection_state=get_param_value(line, "connection-state"),
                comment=get_param_value(line, "comment"),
                line=line
            ))

    # 8. Parse Services
    _DEFAULT_PORTS = {"telnet": 23, "ftp": 21, "www": 80, "ssh": 22, "www-ssl": 443,
                      "api": 8728, "api-ssl": 8729, "winbox": 8291}
    srv_sec = get_section(sections, "/ip service")
    for line in srv_sec:
        name = get_param_value(line, "name")
        port_str = get_param_value(line, "port")
        disabled = get_param_value(line, "disabled") == "yes"
        address = get_param_value(line, "address")
        # Handle both 'set <name> ...' and 'set name=<name> ...'
        if not name:
            # Try parsing 'set telnet disabled=yes' or 'disable telnet'
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == 'set':
                name = parts[1]
            elif len(parts) >= 2 and parts[0] == 'disable':
                name = parts[1]
                disabled = True
        if name:
            port = int(port_str) if (port_str and port_str.isdigit()) else _DEFAULT_PORTS.get(name, 0)
            model.services.append(RouterOSService(
                name=name, port=port, disabled=disabled, address=address
            ))

    # 9. DNS, NTP, SNMP, Logging
    dns_sec = get_section(sections, "/ip dns")
    for line in dns_sec:
        servers_str = get_param_value(line, "servers")
        if servers_str:
            model.dns_servers = [s.strip() for s in servers_str.split(",")]
        model.dns_allow_remote = get_param_value(line, "allow-remote-requests") == "yes"

    ntp_sec = get_section(sections, "/system ntp client")
    for line in ntp_sec:
        model.ntp_enabled = get_param_value(line, "enabled") == "yes"
        servers_str = get_param_value(line, "servers") or get_param_value(line, "primary-ntp")
        if servers_str:
            model.ntp_servers.append(servers_str)
        sec_ntp = get_param_value(line, "secondary-ntp")
        if sec_ntp:
            model.ntp_servers.append(sec_ntp)

    snmp_sec = get_section(sections, "/snmp")
    for line in snmp_sec:
        model.snmp_enabled = get_param_value(line, "enabled") == "yes"

    snmp_comm_sec = get_section(sections, "/snmp community")
    for line in snmp_comm_sec:
        cname = get_param_value(line, "name")
        if cname and get_param_value(line, "addresses") != "0.0.0.0/0":
            model.snmp_community = cname

    syslog_action_sec = get_section(sections, "/system logging action")
    for line in syslog_action_sec:
        target = get_param_value(line, "target")
        remote = get_param_value(line, "remote")
        rport_str = get_param_value(line, "remote-port")
        if target == "remote" and remote:
            model.syslog_enabled = True
            model.syslog_host = remote
            model.syslog_port = int(rport_str) if (rport_str and rport_str.isdigit()) else 514

    # 10. Check scripts for backup routine
    script_sec = get_section(sections, "/system script")
    for line in script_sec:
        source = get_param_value(line, "source") or ""
        if "backup save" in source:
            model.backup_script_exists = True
        if "export file" in source or "export terse" in source:
            model.rsc_export_script_exists = True

    return model
