# -*- coding: utf-8 -*-
"""Test specifically for the user's config with disabled firewall rules"""
import requests
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Simulates user's config: DHCP client, disabled firewall rules, DNS allow-remote, no NTP
USER_CONFIG = """
# RouterOS 7.16.2
/interface bridge
add name=bridge vlan-filtering=yes
/interface bridge port
add bridge=bridge interface=ether2
add bridge=bridge interface=ether3
add bridge=bridge interface=ether4
add bridge=bridge interface=ether5
/interface bridge vlan
add bridge=bridge vlan-ids=1 tagged=bridge untagged=ether2,ether3,ether4,ether5
/ip address
add address=192.168.88.1/24 interface=bridge
/ip dhcp-client
add interface=ether1 name=client1
/ip dhcp-server
add address-pool=default-dhcp interface=bridge name=defconf
/ip dhcp-server network
add address=192.168.88.0/24 gateway=192.168.88.1
/ip pool
add name=default-dhcp ranges=192.168.88.10-192.168.88.254
/ip dns
set allow-remote-requests=yes
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="defconf: accept established" disabled=yes
add chain=input action=drop connection-state=invalid comment="defconf: drop invalid" disabled=yes
add chain=input action=accept protocol=icmp comment="defconf: accept ICMP" disabled=yes
add chain=input action=accept in-interface-list=LAN comment="defconf: accept LAN" disabled=yes
add chain=input action=drop in-interface-list=!LAN comment="defconf: drop all not from LAN" disabled=yes
add chain=forward action=accept ipsec-policy=in,ipsec comment="defconf: accept ipsec" disabled=yes
add chain=forward action=accept connection-state=established,related,untracked comment="defconf: accept established" disabled=yes
add chain=forward action=drop connection-state=invalid comment="defconf: drop invalid forward" disabled=yes
add chain=forward action=drop connection-nat-state=!dstnat in-interface-list=!LAN comment="defconf: drop WAN forward" disabled=yes
/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1
/interface wifi capsman
set enabled=yes
/interface wifi security
add name=sec1 authentication-types=wpa2-psk,wpa3-psk ft=yes passphrase="MyWiFi123"
/interface wifi configuration
add name=cfg1 ssid="HomeNet" security=sec1
"""

BASE = "http://localhost:8899"

def main():
    print("=" * 60)
    print("  Testing False Positive Fixes")
    print("=" * 60)

    try:
        r = requests.get(f"{BASE}/", timeout=5)
        print(f"\nServer: HTTP {r.status_code} OK")
    except:
        print("Server unreachable!")
        sys.exit(1)

    r = requests.post(f"{BASE}/api/analyze", json={"config": USER_CONFIG}, timeout=20)
    assert r.status_code == 200
    d = r.json()

    summary = d["summary"]
    pr = d["production_readiness"]
    print(f"\n  Score:    {summary['score']}")
    print(f"  Issues:   {summary['total_issues']}")
    print(f"  Warnings: {summary['total_warnings']}")
    print(f"  Verdict:  {pr['verdict']}")

    # Collect ALL issues and warnings
    all_issues = []
    all_warnings = []
    all_info = []
    all_fixes = []

    cats = ['l2', 'vlan', 'dhcp', 'wifi', 'security', 'performance',
            'vlan_ext', 'dhcp_ext', 'wifi_ext', 'capsman', 'capsman_ext',
            'firewall', 'routing', 'multiwan', 'script',
            'security_ext', 'monitoring', 'backup', 'services',
            'performance_ext', 'l3']
    for c in cats:
        sec = d.get(c, {})
        if not isinstance(sec, dict):
            continue
        all_issues.extend(sec.get('issues', []))
        all_warnings.extend(sec.get('warnings', []))
        all_info.extend(sec.get('info', []))
        all_fixes.extend(sec.get('fixes', []))

    print(f"\n--- ALL ISSUES ({len(all_issues)}) ---")
    for i in all_issues:
        print(f"  ❌ {i}")

    print(f"\n--- ALL WARNINGS ({len(all_warnings)}) ---")
    for w in all_warnings:
        print(f"  ⚠️ {w}")

    print(f"\n--- ALL INFO ({len(all_info)}) ---")
    for inf in all_info:
        print(f"  ℹ️ {inf}")

    print(f"\n--- CRITICAL FAILURES ---")
    for cf in pr.get('critical_failures', []):
        print(f"  💀 {cf}")

    print(f"\n--- FIXES ({len(all_fixes)}) ---")
    for f in all_fixes[:10]:
        print(f"  🔧 {f}")

    # ASSERTIONS — verify false positive fixes
    print("\n" + "=" * 60)
    print("  Verification Checks")
    print("=" * 60)

    all_text = " ".join(all_issues + all_warnings + all_info)

    # 1. No false DHCP subnet mismatch ERROR (should be at most a warning)
    dhcp_false_positive = any("DHCP" in i and "не відповідає" in i for i in all_issues)
    status = "❌ FAIL" if dhcp_false_positive else "✅ PASS"
    print(f"  {status} — No DHCP subnet false positive in issues")

    # 2. No false default route ERROR
    route_false_positive = any("дефолтний маршрут" in i.lower() or "default route" in i.lower() for i in all_issues)
    route_in_critical = any("маршрут" in cf.lower() for cf in pr.get('critical_failures', []))
    status = "❌ FAIL" if (route_false_positive or route_in_critical) else "✅ PASS"
    print(f"  {status} — No default route false positive (DHCP client detected)")

    # 3. CRITICAL: disabled firewall detected
    fw_disabled_detected = any("вимкнені" in i.lower() and "input" in i.lower() for i in all_issues)
    status = "✅ PASS" if fw_disabled_detected else "❌ FAIL"
    print(f"  {status} — Disabled firewall rules detected as CRITICAL")

    # 4. DNS amplification WITH disabled FW context
    dns_detected = any("DNS" in i and ("Amplification" in i or "remote-requests" in i or "53" in i) for i in all_issues)
    status = "✅ PASS" if dns_detected else "❌ FAIL"
    print(f"  {status} — DNS open resolver correctly detected")

    # 5. No FT warning when CAPsMAN is enabled
    ft_false = any("Fast Transition" in w and "одиночної" in w for w in all_warnings)
    status = "❌ FAIL" if ft_false else "✅ PASS"
    print(f"  {status} — No FT false positive with CAPsMAN enabled")

    # 6. VLAN 1 is info, not warning
    vlan1_in_warnings = any("VLAN 1" in w for w in all_warnings)
    vlan1_in_info = any("VLAN 1" in inf for inf in all_info)
    status = "❌ FAIL" if vlan1_in_warnings else ("✅ PASS" if vlan1_in_info else "⚠️ SKIP (no VLAN 1)")
    print(f"  {status} — VLAN 1 classified as info (not warning)")

    # 7. No duplicates in issues/warnings
    issue_dupes = len(all_issues) != len(set(all_issues))
    warn_dupes = len(all_warnings) != len(set(all_warnings))
    status = "❌ FAIL" if (issue_dupes or warn_dupes) else "✅ PASS"
    print(f"  {status} — No duplicate issues/warnings")

    print("\n" + "=" * 60)
    all_passed = not dhcp_false_positive and not (route_false_positive or route_in_critical) and fw_disabled_detected and dns_detected and not ft_false and not vlan1_in_warnings and not issue_dupes and not warn_dupes
    if all_passed:
        print("  ALL VERIFICATION CHECKS PASSED ✅")
    else:
        print("  SOME CHECKS FAILED ❌")
    print("=" * 60)

if __name__ == "__main__":
    main()
