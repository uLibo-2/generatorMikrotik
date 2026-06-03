# -*- coding: utf-8 -*-
from typing import Dict, Any, List, Tuple
from backend.parsers.ast_parser import RouterOS_AST, ASTNode

def getNodeKey(node: ASTNode) -> str:
    """Helper to extract a unique key for matching nodes across ASTs."""
    if not node.params:
        return ""
    name = node.params.get("name", "").strip('"\'')
    if name:
        return name
    addr = node.params.get("address", "").strip('"\'')
    if addr:
        return addr
    iface = node.params.get("interface", "").strip('"\'')
    if iface:
        # e.g. for bridge port / vlan ports
        pvid = node.params.get("pvid", "")
        return f"{iface}-{pvid}" if pvid else iface
    return ""

def parse_ast_map(ast: RouterOS_AST) -> Dict[Tuple[str, str], ASTNode]:
    node_map = {}
    for node in ast.nodes:
        if node.action == "add":
            key = getNodeKey(node)
            if key:
                node_map[(node.path, key)] = node
    return node_map

def generate_config_diff(orig: str, new: str) -> str:
    res = generate_config_diff_structured(orig, new)

    output = []
    output.append("==================================================")
    output.append(f" ОЦІНКА РИЗИКУ ЗМІН: {res['risk_level']}")
    output.append(f" Пояснення: {res['risk_explanation']}")
    output.append("==================================================")
    output.append("")
    output.append(res["diff"])

    return "\n".join(output)

def generate_config_diff_structured(orig: str, new: str) -> Dict[str, Any]:
    try:
        orig_ast = RouterOS_AST.parse_rsc(orig)
        new_ast = RouterOS_AST.parse_rsc(new)
    except Exception as e:
        return {
            "diff": f"Помилка порівняння AST: {str(e)}",
            "risk_level": "CRITICAL",
            "risk_explanation": "Не вдалося розпарсити конфігурацію в AST."
        }

    orig_map = parse_ast_map(orig_ast)
    new_map = parse_ast_map(new_ast)

    added = []
    removed = []
    modified = []

    # Detect additions and modifications
    for key, new_node in new_map.items():
        path, key_name = key
        if key not in orig_map:
            # Check context path translation
            entity_type = path.replace("/", "").strip()
            added.append(f"+ Added {entity_type.upper()}: '{key_name}'")
        else:
            orig_node = orig_map[key]
            # Compare parameters
            changes = []
            for p_k, p_v in new_node.params.items():
                orig_v = orig_node.params.get(p_k)
                if orig_v != p_v:
                    changes.append(f"  {p_k}: {orig_v or 'None'} -> {p_v}")
            if changes:
                entity_type = path.replace("/", "").strip()
                modified.append(f"~ Modified {entity_type.upper()} '{key_name}':\n" + "\n".join(changes))

    # Detect removals
    for key, orig_node in orig_map.items():
        path, key_name = key
        if key not in new_map:
            entity_type = path.replace("/", "").strip()
            removed.append(f"- Removed {entity_type.upper()}: '{key_name}'")

    # Evaluate Risk Level
    risk_level = "LOW"
    risk_reasons = []

    # Rules for Risk Rating
    # 1. Critical: bridge filtering, identity, ssh/winbox disable, routing removal
    critical_triggers = ["vlan-filtering", "system identity", "ip route remove", "ip service set disabled=yes"]
    # Check modified params for critical items
    for m in modified:
        if "vlan-filtering" in m or "identity" in m.lower():
            risk_level = "CRITICAL"
            risk_reasons.append("Модифікація параметрів мікросхеми VLAN-фільтрації або ідентичності пристрою.")

    for r in removed:
        if "route" in r.lower() or "interface" in r.lower() or "bridge" in r.lower():
            risk_level = "CRITICAL"
            risk_reasons.append("Видалення системних інтерфейсів, мостів або маршрутів за замовчуванням.")

    # 2. High: IP subnet changes, DHCP server pool shifts
    if risk_level != "CRITICAL":
        for m in modified:
            if "address" in m.lower() or "ranges" in m.lower() or "pool" in m.lower():
                risk_level = "HIGH"
                risk_reasons.append("Зміна IP-адрес, DHCP-пулів або конфігурації підмереж.")
        for r in removed:
            if "dhcp" in r.lower() or "pool" in r.lower():
                risk_level = "HIGH"
                risk_reasons.append("Видалення служб DHCP-сервера чи пулу адрес.")

    # 3. Medium: adding firewall filter rules, vlan configurations
    if risk_level not in ["CRITICAL", "HIGH"]:
        if added:
            for a in added:
                if "firewall" in a.lower() or "vlan" in a.lower():
                    risk_level = "MEDIUM"
                    risk_reasons.append("Додавання нових правил брандмауера чи VLAN сегментів.")
        for m in modified:
            if "firewall" in m.lower() or "wifi" in m.lower() or "wireless" in m.lower():
                risk_level = "MEDIUM"
                risk_reasons.append("Оновлення параметрів фільтрації або Wi-Fi налаштувань.")

    # Default to LOW if nothing else matches
    if not risk_reasons:
        if added or removed or modified:
            risk_level = "LOW"
            risk_reasons.append("Незначні зміни конфігурації (коментарі, додаткові некритичні параметри).")
        else:
            risk_level = "LOW"
            risk_reasons.append("Змін у структурі конфігурації не виявлено.")

    diff_lines = []
    if added:
        diff_lines.extend(added)
    if modified:
        diff_lines.extend(modified)
    if removed:
        diff_lines.extend(removed)

    diff_text = "\n".join(diff_lines) if diff_lines else "Конфігурації ідентичні."

    return {
        "diff": diff_text,
        "risk_level": risk_level,
        "risk_explanation": "; ".join(risk_reasons)
    }
