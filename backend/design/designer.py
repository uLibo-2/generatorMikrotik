# -*- coding: utf-8 -*-
"""
MikroTik IP Plan Designer & Site Profiles Engine
Enforces profile validation, non-overlapping subnets, and documentation compilation.
"""
import ipaddress
from typing import List, Dict, Any

PROFILES = {
    "home": {
        "title": "Home (Домашній)",
        "description": "Базовий домашній профіль: окремі VLAN для сім'ї, гостей та розумного дому (IoT).",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "192.168.88.0/24", "gateway": "192.168.88.1"},
            {"id": 20, "name": "Staff_LAN", "subnet": "192.168.10.0/24", "gateway": "192.168.10.1"},
            {"id": 30, "name": "Guest_WiFi", "subnet": "192.168.20.0/24", "gateway": "192.168.20.1"},
            {"id": 40, "name": "IoT_Smart", "subnet": "192.168.30.0/24", "gateway": "192.168.30.1"}
        ]
    },
    "small_office": {
        "title": "Small Office (Малий офіс)",
        "description": "Профіль для невеликої фірми. Захищений менеджмент, окремі мережі для персоналу та гостей.",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.10.10.0/24", "gateway": "10.10.10.1"},
            {"id": 20, "name": "Staff_LAN", "subnet": "10.10.20.0/24", "gateway": "10.10.20.1"},
            {"id": 30, "name": "Guest_WiFi", "subnet": "10.10.30.0/24", "gateway": "10.10.30.1"},
            {"id": 40, "name": "IoT_Devices", "subnet": "10.10.40.0/24", "gateway": "10.10.40.1"}
        ]
    },
    "medium_office": {
        "title": "Medium Office (Середній офіс)",
        "description": "Мережа для офісу середнього розміру з виділеною VoIP телефонією та камерами відеонагляду (CCTV).",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.20.10.0/24", "gateway": "10.20.10.1"},
            {"id": 20, "name": "Staff_LAN", "subnet": "10.20.20.0/24", "gateway": "10.20.20.1"},
            {"id": 30, "name": "Guest_WiFi", "subnet": "10.20.30.0/24", "gateway": "10.20.30.1"},
            {"id": 40, "name": "VoIP_Phones", "subnet": "10.20.40.0/24", "gateway": "10.20.40.1"},
            {"id": 50, "name": "CCTV_Cameras", "subnet": "10.20.50.0/24", "gateway": "10.20.50.1"}
        ]
    },
    "warehouse": {
        "title": "Warehouse (Складський комплекс)",
        "description": "Оптимізовано для підключення сканерів штрихкодів, терміналів збору даних та систем логістики.",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.30.10.0/24", "gateway": "10.30.10.1"},
            {"id": 20, "name": "Office_Staff", "subnet": "10.30.20.0/24", "gateway": "10.30.20.1"},
            {"id": 30, "name": "Scanners_WiFi", "subnet": "10.30.30.0/24", "gateway": "10.30.30.1"},
            {"id": 50, "name": "CCTV_Secure", "subnet": "10.30.50.0/24", "gateway": "10.30.50.1"}
        ]
    },
    "retail_store": {
        "title": "Retail Store (Магазин / Торгова точка)",
        "description": "Виділений контур безпеки для касових POS терміналів, банківських терміналів та гостьового WiFi.",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.40.10.0/24", "gateway": "10.40.10.1"},
            {"id": 20, "name": "POS_Terminals", "subnet": "10.40.20.0/24", "gateway": "10.40.20.1"},
            {"id": 30, "name": "Guest_WiFi", "subnet": "10.40.30.0/24", "gateway": "10.40.30.1"},
            {"id": 40, "name": "IoT_Signage", "subnet": "10.40.40.0/24", "gateway": "10.40.40.1"}
        ]
    },
    "hotel": {
        "title": "Hotel (Готельний комплекс)",
        "description": "Велика кількість хостів у гостьовому сегменті з клієнтською ізоляцією.",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.50.10.0/24", "gateway": "10.50.10.1"},
            {"id": 20, "name": "Administration", "subnet": "10.50.20.0/24", "gateway": "10.50.20.1"},
            {"id": 30, "name": "Hotel_Guests", "subnet": "10.50.32.0/22", "gateway": "10.50.32.1"},
            {"id": 50, "name": "CCTV_Cameras", "subnet": "10.50.50.0/24", "gateway": "10.50.50.1"}
        ]
    },
    "school": {
        "title": "School (Школа / Академія)",
        "description": "Поділ на класи, вчителів, лабораторії. Контентна фільтрація DNS в гостьових мережах.",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.60.10.0/24", "gateway": "10.60.10.1"},
            {"id": 20, "name": "Teachers_LAN", "subnet": "10.60.20.0/24", "gateway": "10.60.20.1"},
            {"id": 30, "name": "Students_WiFi", "subnet": "10.60.32.0/22", "gateway": "10.60.32.1"},
            {"id": 40, "name": "Lab_Computers", "subnet": "10.60.40.0/24", "gateway": "10.60.40.1"}
        ]
    },
    "industrial": {
        "title": "Industrial (Виробництво / Завод)",
        "description": "Промисловий профіль. Ізольований контур SCADA/PLC контролерів від корпоративної мережі.",
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.70.10.0/24", "gateway": "10.70.10.1"},
            {"id": 20, "name": "Corporate_LAN", "subnet": "10.70.20.0/24", "gateway": "10.70.20.1"},
            {"id": 30, "name": "SCADA_PLC", "subnet": "10.70.30.0/24", "gateway": "10.70.30.1"},
            {"id": 50, "name": "CCTV_Security", "subnet": "10.70.50.0/24", "gateway": "10.70.50.1"}
        ]
    },
    "isp_client": {
        "title": "ISP Client (Клієнт провайдера)",
        "description": "Підключення домашнього офісу без складної типізації VLAN. Один локальний міст bridge.",
        "vlans": [
            {"id": 1, "name": "LAN_Bridge", "subnet": "192.168.1.0/24", "gateway": "192.168.1.1"}
        ]
    },
    "datacenter": {
        "title": "Data Center (Дата-центр Edge)",
        "description": "Edge маршрутизація: транзитні підмережі BGP пірингу, сервери та зона управління DMZ.",
        "vlans": [
            {"id": 10, "name": "DC_Management", "subnet": "172.16.10.0/24", "gateway": "172.16.10.1"},
            {"id": 20, "name": "DMZ_Servers", "subnet": "172.16.20.0/24", "gateway": "172.16.20.1"},
            {"id": 30, "name": "Prod_Clusters", "subnet": "172.16.30.0/24", "gateway": "172.16.30.1"}
        ]
    }
}

def verify_ip_plan(vlan_list: List[Dict[str, Any]]) -> List[str]:
    """
    Validates a designed IP Plan:
    1. Compiles subnets and checks for syntax errors.
    2. Enforces non-overlapping check using overlaps().
    3. Validates gateway ranges.
    4. Ensures unique VLAN IDs.
    """
    errors = []
    networks = []
    vlan_ids = set()
    vlan_names = set()

    for idx, v in enumerate(vlan_list):
        vid_str = str(v.get("id", "")).strip()
        name = str(v.get("name", "")).strip()
        subnet_str = str(v.get("subnet", "")).strip()
        gw_str = str(v.get("gateway", "")).strip()

        # 1. VLAN ID Validation
        if not vid_str:
            errors.append(f"Рядок {idx+1}: Відсутній VLAN ID")
            continue
        try:
            vid = int(vid_str)
            if vid < 1 or vid > 4094:
                errors.append(f"Рядок {idx+1}: VLAN ID '{vid}' має бути в межах 1-4094")
            elif vid in vlan_ids:
                errors.append(f"Рядок {idx+1}: Дублювання VLAN ID '{vid}'")
            else:
                vlan_ids.add(vid)
        except ValueError:
            errors.append(f"Рядок {idx+1}: Невірний формат VLAN ID '{vid_str}'")

        # 2. VLAN Name Validation
        if not name:
            errors.append(f"Рядок {idx+1}: Відсутня назва зони (VLAN Name)")
        elif name in vlan_names:
            errors.append(f"Рядок {idx+1}: Дублювання назви зони '{name}'")
        else:
            vlan_names.add(name)

        # 3. Subnet Validation
        if not subnet_str:
            errors.append(f"Зона '{name}': Відсутня підмережа")
            continue
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
            networks.append((name, net))
        except Exception as e:
            errors.append(f"Зона '{name}': Невірний формат підмережі '{subnet_str}' ({e})")
            continue

        # 4. Gateway Validation
        if not gw_str:
            errors.append(f"Зона '{name}': Відсутній шлюз (Gateway)")
        else:
            try:
                gw = ipaddress.ip_address(gw_str)
                if gw not in net:
                    errors.append(f"Зона '{name}': Шлюз '{gw}' не належить до підмережі '{net}'")
            except Exception as e:
                errors.append(f"Зона '{name}': Невірний формат IP адреси шлюзу '{gw_str}' ({e})")

    # 5. Overlap Detection
    for i in range(len(networks)):
        name_a, net_a = networks[i]
        for j in range(i + 1, len(networks)):
            name_b, net_b = networks[j]
            if net_a.overlaps(net_b):
                errors.append(f"Конфлікт підмереж: Мережа зони '{name_a}' ({net_a}) перетинається з зоною '{name_b}' ({net_b})")

    return errors


def generate_connectivity_scheme(template_id: str, variables: Dict[str, str]) -> str:
    """Generates an ASCII layout scheme of the network topology connection mapping."""
    scheme = []
    scheme.append("==========================================================================")
    scheme.append(f"        СХЕМА ПІДКЛЮЧЕННЯ ТА КОМУТАЦІЇ ДЛЯ ШАБЛОНУ '{template_id.upper()}' ")
    scheme.append("==========================================================================")

    scheme.append("\nФізична топологія та порти:")
    scheme.append("  [ WAN Провайдер ] ")
    scheme.append("         │")
    scheme.append(f"         ▼ (Кабель)")
    scheme.append(f"  [ MikroTik {variables.get('WAN_INTERFACE', 'ether1')} (WAN) ]")
    scheme.append("  [ MikroTik Bridge 'bridge' (LAN) ]")
    scheme.append("         ├── ether2  =>  Зона: Staff / Локальні ПК")
    scheme.append("         ├── ether3  =>  Зона: Guest / Гостьові пристрої")
    scheme.append("         └── ether4  =>  Зона: IoT / Smart Home")

    if "capsman" in template_id or "wifi" in template_id:
        scheme.append("\nРадіоінтерфейси (Standalone / CAPsMAN):")
        scheme.append("  [ wifi1 (2.4 GHz) ] ── SSID: " + variables.get("SITE_NAME", "Office") + "-Staff (VLAN " + variables.get("STAFF_VLAN", "20") + ")")
        scheme.append("  [ wifi2 (5 GHz) ]   ── SSID: " + variables.get("SITE_NAME", "Office") + "-Guest (VLAN " + variables.get("GUEST_VLAN", "30") + ")")

    if "wireguard" in template_id:
        scheme.append("\nВіртуальні тунелі:")
        scheme.append(f"  [ Interface: wg_server (UDP port {variables.get('WIREGUARD_PORT', '13231')}) ]")
        scheme.append("         └── Peer: 10.250.0.2  =>  Маршрут до Admin Mobile")

    scheme.append("\n==========================================================================")
    return "\n".join(scheme)


def generate_vlan_table_data(variables: Dict[str, str]) -> List[Dict[str, Any]]:
    """Compiles structured VLAN configuration records."""
    table = []

    # Check variables to fetch configured values
    vlans_to_add = [
        ("MGMT_VLAN", "MGMT_SUBNET", "MGMT_GATEWAY", "Менеджмент та Управління"),
        ("STAFF_VLAN", "STAFF_SUBNET", "STAFF_GATEWAY", "Внутрішня мережа персоналу"),
        ("GUEST_VLAN", "GUEST_SUBNET", "GUEST_GATEWAY", "Гостьова бездротова зона"),
        ("IOT_VLAN", "IOT_SUBNET", "IOT_GATEWAY", "Пристрої розумного дому"),
        ("CCTV_VLAN", "CCTV_SUBNET", "CCTV_GATEWAY", "Камери відеонагляду")
    ]

    for v_id_key, subnet_key, gw_key, desc in vlans_to_add:
        v_id = variables.get(v_id_key)
        if v_id:
            table.append({
                "vlan_id": int(v_id),
                "name": v_id_key.replace("_VLAN", "").lower(),
                "subnet": variables.get(subnet_key, "N/A"),
                "gateway": variables.get(gw_key, "N/A"),
                "description": desc
            })

    # Fallback to default list if variables are blank
    if not table:
        table.append({"vlan_id": 1, "name": "default", "subnet": "192.168.88.0/24", "gateway": "192.168.88.1", "description": "Стандартний локальний міст"})

    return sorted(table, key=lambda x: x["vlan_id"])


def generate_markdown_documentation(template_id: str, variables: Dict[str, str], vlan_table: List[Dict[str, Any]]) -> str:
    """Generates a complete deployment guide in Markdown."""
    doc = []
    doc.append(f"# Посібник з впровадження конфігурації '{template_id.upper()}'")
    doc.append(f"**Площадка:** {variables.get('SITE_NAME', 'Office-Router')} | **Регіон:** {variables.get('COUNTRY', 'Ukraine')}\n")

    doc.append("## 1. Загальний опис архітектури")
    doc.append("Дана конфігурація згенерована автоматично на базі професійних рекомендацій вендора MikroTik.")
    doc.append(f"Всі локальні інтерфейси об'єднано у віртуальний міст `{variables.get('LAN_BRIDGE', 'bridge')}` з активованою функцією VLAN Filtering.")
    doc.append(f"Вихід у зовнішній світ здійснюється через фізичний WAN порт `{variables.get('WAN_INTERFACE', 'ether1')}`.\n")

    doc.append("## 2. Таблиця розподілу VLAN та IP адрес")
    doc.append("| VLAN ID | Назва інтерфейсу | Підмережа | IP Шлюзу | Призначення |")
    doc.append("|---|---|---|---|---|")
    for v in vlan_table:
        doc.append(f"| **{v['vlan_id']}** | vlan_{v['name']} | `{v['subnet']}` | `{v['gateway']}` | {v['description']} |")
    doc.append("")

    doc.append("## 3. Інструкція з первинного встановлення")
    doc.append("1. Підключіть мережевий кабель від провайдера до порту `" + variables.get('WAN_INTERFACE', 'ether1') + "`.")
    doc.append("2. Підключіть ваш ПК до будь-якого вільного LAN порту (наприклад, ether2).")
    doc.append("3. Відкрийте утиліту Winbox, знайдіть роутер у вкладці Neighbors та підключіться по MAC адресі.")
    doc.append("4. Перейдіть до меню `New Terminal` та скопіюйте туди повний текст згенерованого файлу `.rsc` конфігурації.")
    doc.append("5. Після завершення імпорту пристрій автоматично перенаправиться. З'єднання буде оновлено згідно з обраною VLAN адресацією.\n")

    doc.append("## 4. Заходи безпеки (Security Baseline)")
    doc.append("- **IP Services**: Небезпечні служби керування роутером (`telnet`, `ftp`) повністю вимкнено.")
    doc.append("- **SSH Security**: Активовано опцію `strong-crypto=yes` (відкидаються слабкі шифри).")
    doc.append("- **Firewall**: Налаштовано ланцюжок `input` для блокування доступу до DNS та Winbox з WAN інтерфейсу.")
    doc.append("- **NTP**: Маршрутизатор автоматично синхронізує час через пул `" + variables.get('DNS_PRIMARY', 'pool.ntp.org') + "` для коректного логування.")

    return "\n".join(doc)
