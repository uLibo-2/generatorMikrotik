from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel

@registry.register
class AuditBridgeVlanFiltering(AuditPlugin):
    id = "BP-L2-001"
    category = "l2"
    severity = "high"
    confidence = 100
    title = "Bridge VLAN Filtering"
    description = "Перевірка увімкнення VLAN Filtering на комутаційному мосту."
    impact = "Якщо vlan-filtering=no, ізоляція VLAN не діятиме, і трафік різних VLAN зможе протікати між портами без контролю (витік VLAN)."
    best_practice = "Встановіть vlan-filtering=yes на робочому bridge після налаштування всіх портів."
    resolution = "Увімкнути фільтрацію VLAN за допомогою команди CLI."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        for br in model.bridges:
            if not br.vlan_filtering:
                warnings.append(f"⚠️ vlan-filtering=no на bridge '{br.name}' — VLAN ізоляція не працює")
                fixes.append(f"/interface bridge set [find name={br.name}] vlan-filtering=yes")
            else:
                info.append(f"✅ Фільтрацію VLAN (vlan-filtering=yes) успішно активовано на bridge '{br.name}'")

        if not model.bridges:
            warnings.append("⚠️ Не знайдено жодного створеного мосту (bridge)")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditBridgeSTP(AuditPlugin):
    id = "BP-L2-002"
    category = "l2"
    severity = "medium"
    confidence = 95
    title = "Spanning Tree Protocol (STP)"
    description = "Перевірка захисту від комутаційних петель за допомогою протоколів Spanning Tree."
    impact = "Без увімкненого STP/RSTP/MSTP випадкове кабельне з'єднання двох LAN портів спричинить мережевий шторм (broadcast storm), що повністю покладе мережу."
    best_practice = "Завжди використовувати щонайменше протокол RSTP (Rapid Spanning Tree) на мостах."
    resolution = "Перевести міст у режим протоколу rstp."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # We check raw lines since RSTP is default in RouterOS v7 but can be overridden
        # bridge_sec in raw_sections
        bridge_lines = model.raw_sections.get("/interface bridge", [])
        for line in bridge_lines:
            name = line.split("add")[-1].split("name=")[-1].split()[0].replace('"', '') if "name=" in line else "bridge"
            if "protocol-mode=none" in line:
                warnings.append(f"⚠️ STP вимкнено (protocol-mode=none) на bridge '{name}'")
                fixes.append(f"/interface bridge set [find name={name}] protocol-mode=rstp")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditBridgePortsIngress(AuditPlugin):
    id = "BP-L2-003"
    category = "l2"
    severity = "low"
    confidence = 90
    title = "Ingress Filtering on Bridge Ports"
    description = "Перевірка налаштування ingress-filtering на фізичних портах мосту."
    impact = "Без ingress-filtering=yes комутатор може приймати пакети з тегами VLAN, які не налаштовані на цьому порту, створюючи ризики безпеки."
    best_practice = "Вмикати ingress-filtering=yes для всіх активних портів мосту."
    resolution = "Ввімкнути ingress-filtering на відповідних портах мосту."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        for br in model.bridges:
            for port in br.ports:
                if not port.ingress_filtering:
                    warnings.append(f"⚠️ {port.interface}: Рекомендується увімкнути ingress-filtering=yes для безпеки VLAN")
                    fixes.append(f"/interface bridge port set [find interface={port.interface}] ingress-filtering=yes")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditVlanTableConsistency(AuditPlugin):
    id = "BP-L2-004"
    category = "l2"
    severity = "critical"
    confidence = 98
    title = "VLAN Bridge Table Mapping"
    description = "Аналіз узгодженості PVID портів мосту із записами в таблиці Bridge VLAN."
    impact = "Якщо PVID порту відсутній у таблиці `/interface bridge vlan`, вхідний нетегований трафік буде відкинуто або ізольовано."
    best_practice = "Кожен PVID порту мосту повинен мати відповідний запис untagged (або tagged) у таблиці bridge vlan."
    resolution = "Створити відповідний запис у таблиці bridge vlan."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        for br in model.bridges:
            pvid_ports = {}
            tagged_vlans = {}
            untagged_vlans = {}

            for port in br.ports:
                pvid_ports[port.interface] = port.pvid

            for vlan in br.vlans:
                for vid in vlan.vlan_ids:
                    for iface in vlan.tagged:
                        tagged_vlans.setdefault(iface, set()).add(vid)
                    for iface in vlan.untagged:
                        untagged_vlans.setdefault(iface, set()).add(vid)

            # Verification: PVID must be in tagged or untagged
            for iface, pvid in pvid_ports.items():
                in_tagged = pvid in tagged_vlans.get(iface, set())
                in_untagged = pvid in untagged_vlans.get(iface, set())
                if not in_tagged and not in_untagged:
                    issues.append(f"❌ {iface}: PVID={pvid} не знайдено у bridge vlan table для bridge '{br.name}'")
                    fixes.append(f"/interface bridge vlan add bridge={br.name} vlan-ids={pvid} untagged={iface}")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditNativeVlanOne(AuditPlugin):
    id = "BP-L2-005"
    category = "l2"
    severity = "info"
    confidence = 95
    title = "Native VLAN 1 usage"
    description = "Перевірка використання дефолтного VLAN ID 1 для користувацького трафіку."
    impact = "Використання VLAN 1 є загрозою безпеки (VLAN Hopping), оскільки він є службовим дефолтним ідентифікатором за замовчуванням."
    best_practice = "Рекомендується перевести весь клієнтський трафік на інші VLAN ID (наприклад, 10, 20, 99 для адміністрування)."
    resolution = "Використовувати власні ідентифікатори VLAN замість VLAN 1."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        vlan_1_found = False
        for br in model.bridges:
            for vlan in br.vlans:
                if 1 in vlan.vlan_ids:
                    vlan_1_found = True
                    break
        for v in model.vlans:
            if v.vlan_id == 1:
                vlan_1_found = True

        if vlan_1_found:
            info.append("ℹ️ VLAN 1 використовується як native LAN — для підвищення безпеки рекомендується використовувати інший VLAN ID")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditOrphanVlans(AuditPlugin):
    id = "BP-L2-006"
    category = "l2"
    severity = "high"
    confidence = 98
    title = "Orphan VLAN Interfaces"
    description = "Пошук VLAN інтерфейсів, які створені, але не задіяні на мосту, або навпаки."
    impact = "Ситуація, коли інтерфейс VLAN створено, але не додано у `/interface bridge vlan` (або навпаки), призведе до втрати зв'язку для цього VLAN."
    best_practice = "Для кожного VLAN інтерфейсу повинен існувати запис у таблиці bridge vlan з цим ID."
    resolution = "Додати VLAN у таблицю мосту або створити інтерфейс."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        declared_vlans = {v.vlan_id for v in model.vlans}
        bridge_mapped_vlans = set()

        for br in model.bridges:
            for vlan in br.vlans:
                for vid in vlan.vlan_ids:
                    bridge_mapped_vlans.add(vid)

        # 1. VLAN interface exists, but not in bridge vlan table
        for vlan in model.vlans:
            if vlan.vlan_id not in bridge_mapped_vlans and vlan.vlan_id != 1:
                issues.append(f"❌ VLAN {vlan.vlan_id} створено як інтерфейс '{vlan.name}', але не додано в таблицю мосту (bridge vlan)")
                # Default fix: add it to bridge vlan tagging CPU (usually bridge name itself is CPU port)
                bridge_name = model.bridges[0].name if model.bridges else "bridge"
                fixes.append(f"/interface bridge vlan add bridge={bridge_name} vlan-ids={vlan.vlan_id} tagged={bridge_name}")

        # 2. VLAN exists in bridge vlan table, but no interface VLAN exists
        for vid in bridge_mapped_vlans:
            if vid not in declared_vlans and vid != 1:
                warnings.append(f"⚠️ VLAN {vid} прописано в таблиці мосту, але для нього немає інтерфейсу '/interface vlan'")
                bridge_name = model.bridges[0].name if model.bridges else "bridge"
                fixes.append(f"/interface vlan add name=vlan{vid} vlan-id={vid} interface={bridge_name}")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditHardwareOffload(AuditPlugin):
    id = "BP-L2-007"
    category = "l2"
    severity = "medium"
    confidence = 90
    title = "Hardware Offloading (HW Offload)"
    description = "Перевірка підтримки апаратного прискорення на портах мосту."
    impact = "Якщо hw=no на портах, весь трафік комутації обробляється процесором (CPU), що створює велике навантаження та ріже пропускну здатність гігабітних портів до 100-200 Мбіт/с."
    best_practice = "Завжди залишати увімкненим апаратне прискорення (hw=yes) на фізичних портах мосту."
    resolution = "Увімкнути апаратне прискорення для порту мосту."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Hardware limits mapping
        legacy_switches = ["CRS109", "CRS112", "CRS125", "CRS212", "CRS226"]
        is_legacy = any(hw in model.hardware for hw in legacy_switches)

        for br in model.bridges:
            if br.vlan_filtering and is_legacy:
                warnings.append(f"⚠️ Увага! {model.hardware} не підтримує апаратний vlan-filtering. Увімкнення vlan-filtering=yes переведе комутацію на CPU!")

            for port in br.ports:
                if not port.hw and "ether" in port.interface:
                    warnings.append(f"⚠️ {port.interface}: Апаратне прискорення вимкнено (hw=no) — трафік навантажуватиме процесор")
                    fixes.append(f"/interface bridge port set [find interface={port.interface}] hw=yes")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
