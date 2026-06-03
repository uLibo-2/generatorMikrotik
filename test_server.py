# -*- coding: utf-8 -*-
import requests
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

CONFIG_WITH_ISSUES = """
# by RouterOS 7.14.2
/interface bridge
add name=bridge vlan-filtering=no
/interface bridge port
add bridge=bridge interface=ether2 pvid=10
/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
/ip neighbor discovery-settings
set discover-interface-list=all
/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1
/ip dhcp-client
add interface=ether1 disabled=no add-default-route=yes
"""

CONFIG_OK = """
# by RouterOS 7.14.2
/interface bridge
add name=bridge vlan-filtering=yes
/interface bridge port
add bridge=bridge interface=ether2 pvid=10
/interface bridge vlan
add bridge=bridge tagged=bridge untagged=ether2 vlan-ids=10
/interface vlan
add interface=bridge name=vlan10 vlan-id=10
/ip address
add address=192.168.10.1/24 interface=vlan10
/ip dhcp-server
add interface=vlan10 name=dhcp-vlan10 address-pool=pool-vlan10 disabled=no
/ip pool
add name=pool-vlan10 ranges=192.168.10.10-192.168.10.254
/ip dhcp-server network
add address=192.168.10.0/24 gateway=192.168.10.1
/ip firewall nat
add chain=srcnat action=masquerade out-interface=ether1
/ip firewall filter
add chain=forward action=fasttrack-connection connection-state=established,related
/ip dhcp-client
add interface=ether1 disabled=no add-default-route=yes
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set winbox port=8291 disabled=no
/ip neighbor discovery-settings
set discover-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/system ntp client
set enabled=yes servers=0.pool.ntp.org
"""

BASE = "http://localhost:8899"

def test_analyze(label, config):
    r = requests.post(f"{BASE}/api/analyze", json={"config": config}, timeout=20)
    assert r.status_code == 200, f"Status {r.status_code}"
    d = r.json()
    summary = d["summary"]
    pr = d["production_readiness"]
    print(f"\n=== {label} ===")
    print(f"  Score:    {summary['score']}")
    print(f"  Issues:   {summary['total_issues']}")
    print(f"  Warnings: {summary['total_warnings']}")
    print(f"  Verdict:  {pr['verdict']}")
    for cat in ['l2', 'vlan', 'dhcp', 'wifi', 'security', 'performance']:
        sec = d.get(cat, {})
        i = len(sec.get('issues', []))
        w = len(sec.get('warnings', []))
        f = len(sec.get('fixes', []))
        if i or w or f:
            print(f"  [{cat}] issues={i} warnings={w} fixes={f}")
    if pr.get('critical_failures'):
        print("  Critical failures:")
        for cf in pr['critical_failures'][:3]:
            print(f"    - {cf[:100]}")
    return d

def test_rebuild(config):
    r = requests.post(f"{BASE}/api/analyze/rebuild", json={"config": config, "profile": "secure"}, timeout=30)
    assert r.status_code == 200, f"Rebuild status {r.status_code}"
    d = r.json()
    print(f"\n=== REBUILD / AUTOFIX TEST ===")

    # Check remedied_original
    rem = d.get('remedied_original', '')
    print(f"  Remedied original: {len(rem)} chars")
    assert len(rem) > 50, "Remedied original too short"

    # Check refactored clean
    ref = d.get('refactored_clean', '')
    print(f"  Refactored clean:  {len(ref)} chars")
    assert len(ref) > 50, "Refactored clean too short"

    # Check diff
    diff = d.get('diff', '')
    print(f"  Diff:              {len(diff)} chars")

    # Impact analysis
    impact = d.get('impact_analysis', [])
    print(f"  Impact warnings:   {len(impact)}")
    for imp in impact[:2]:
        print(f"    - {imp[:80]}")

    # Complexity
    cpx = d.get('complexity', {})
    print(f"  Complexity score:  {cpx.get('score', 0)} ({cpx.get('description', '?')})")
    print(f"    VLANs={cpx.get('vlans', 0)} SSIDs={cpx.get('ssids', 0)} DHCP={cpx.get('dhcp_servers', 0)} FW={cpx.get('firewall_rules', 0)}")

    # Dry Run
    dryrun = d.get('dry_run', {})
    print(f"  Dry-Run status:    {dryrun.get('status', '?')}")
    remaining = dryrun.get('remaining_issues', [])
    if remaining:
        print(f"    Remaining issues: {len(remaining)}")
        for ri in remaining[:3]:
            print(f"      - {ri[:80]}")

    # Plugins log (Explain Like Engineer)
    plugins = d.get('plugins_log', [])
    print(f"  Plugin checks:     {len(plugins)}")
    for p in plugins[:3]:
        fixes_cnt = len(p.get('fixes', []))
        if fixes_cnt:
            print(f"    [{p['id']}] {p['title']} -> {fixes_cnt} fix(es), severity={p['severity']}, confidence={p['confidence']}%")

    return d

def test_report(config):
    r = requests.post(f"{BASE}/api/report/generate", json={"config": config}, timeout=20)
    assert r.status_code == 200, f"Report status {r.status_code}"
    d = r.json()
    report = d.get('report', '')
    print(f"\n=== REPORT TEST ===")
    print(f"  Report length: {len(report)} chars")
    print(f"  First line: {report.splitlines()[0] if report else 'empty'}")

def test_sample():
    r = requests.get(f"{BASE}/api/sample-config", timeout=5)
    assert r.status_code == 200
    d = r.json()
    print(f"\n=== SAMPLE CONFIG ===")
    print(f"  Length: {len(d.get('config',''))} chars")

def test_history():
    r = requests.get(f"{BASE}/api/history", timeout=5)
    assert r.status_code == 200
    d = r.json()
    print(f"\n=== HISTORY ===")
    print(f"  Records: {len(d)}")

def test_compare():
    r = requests.post(f"{BASE}/api/compare", json={"config_old": CONFIG_WITH_ISSUES, "config_new": CONFIG_OK}, timeout=10)
    assert r.status_code == 200
    d = r.json()
    diff = d.get('diff', '')
    print(f"\n=== COMPARE TEST ===")
    print(f"  Diff: {len(diff)} chars, {diff.count(chr(10))} lines")

if __name__ == "__main__":
    print("=" * 60)
    print("  MikroTik Platform v2.5 — Full API Test Suite")
    print("=" * 60)
    print(f"Server: {BASE}")

    try:
        r = requests.get(f"{BASE}/", timeout=5)
        print(f"\nServer health: HTTP {r.status_code} OK")
    except Exception as e:
        print(f"Server UNREACHABLE: {e}")
        sys.exit(1)

    test_analyze("CONFIG WITH ISSUES", CONFIG_WITH_ISSUES)
    test_analyze("CLEAN CONFIG", CONFIG_OK)
    test_rebuild(CONFIG_WITH_ISSUES)
    test_report(CONFIG_WITH_ISSUES)
    test_compare()
    test_sample()
    test_history()

    print("\n" + "=" * 60)
    print("  ALL TESTS PASSED ✅")
    print("=" * 60)
