# -*- coding: utf-8 -*-
"""
MikroTik Config Templates Library
Contains 16 parameterized templates for various network scenarios.
"""

TEMPLATES = {
    "home_basic": {
        "title": "Home Basic",
        "description": "Проста конфігурація для домашнього роутера без VLAN. Базовий Firewall, NAT та standalone WiFi.",
        "variables": {
            "SITE_NAME": "Home-Router",
            "WAN_INTERFACE": "ether1",
            "LAN_BRIDGE": "bridge",
            "STAFF_SUBNET": "192.168.88.0/24",
            "STAFF_GATEWAY": "192.168.88.1",
            "DNS_PRIMARY": "1.1.1.1",
            "DNS_SECONDARY": "8.8.8.8",
            "COUNTRY": "Ukraine",
            "TIMEZONE": "Europe/Kyiv"
        },
        "config": """# model = hAP ax3
/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}" vlan-filtering=no comment="Local bridge"
/interface bridge port
add bridge="{{LAN_BRIDGE}}" interface=ether2
add bridge="{{LAN_BRIDGE}}" interface=ether3
add bridge="{{LAN_BRIDGE}}" interface=ether4
add bridge="{{LAN_BRIDGE}}" interface=wifi1
add bridge="{{LAN_BRIDGE}}" interface=wifi2
/ip address add address="{{STAFF_GATEWAY}}/24" interface="{{LAN_BRIDGE}}"
/ip pool add name=dhcp_pool ranges=192.168.88.10-192.168.88.254
/ip dhcp-server add name=dhcp_lan interface="{{LAN_BRIDGE}}" address-pool=dhcp_pool disabled=no lease-time=8h
/ip dhcp-server network add address="{{STAFF_SUBNET}}" gateway="{{STAFF_GATEWAY}}" dns-server="{{DNS_PRIMARY}},{{DNS_SECONDARY}}"
/ip dhcp-client add interface="{{WAN_INTERFACE}}" disabled=no add-default-route=yes use-peer-dns=yes
/ip dns set servers="{{DNS_PRIMARY}},{{DNS_SECONDARY}}" allow-remote-requests=yes
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="Accept established/related"
add chain=input action=drop connection-state=invalid comment="Drop invalid"
add chain=input action=accept protocol=icmp comment="Accept ICMP"
add chain=input action=accept in-interface="{{LAN_BRIDGE}}" comment="Accept LAN"
add chain=input action=drop in-interface-list=!LAN comment="Drop all other input"
add chain=forward action=fasttrack-connection connection-state=established,related hw-offload=yes comment="FastTrack"
add chain=forward action=accept connection-state=established,related comment="Accept established/related"
add chain=forward action=drop connection-state=invalid comment="Drop invalid"
add chain=forward action=accept in-interface="{{LAN_BRIDGE}}" out-interface="{{WAN_INTERFACE}}" comment="Allow LAN to WAN"
add chain=forward action=drop connection-nat-state=!dstnat comment="Drop non-NAT WAN traffic"
/ip firewall nat add chain=srcnat action=masquerade out-interface="{{WAN_INTERFACE}}"
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip neighbor discovery-settings set discover-interface-list=LAN
/system clock set time-zone-name="{{TIMEZONE}}"
"""
    },
    "home_advanced": {
        "title": "Home Advanced",
        "description": "Просунута домашня мережа з VLAN (Staff, Guest, IoT), FastTrack та налаштуванням WireGuard.",
        "variables": {
            "SITE_NAME": "Home-Max",
            "WAN_INTERFACE": "ether1",
            "LAN_BRIDGE": "bridge",
            "MGMT_VLAN": "10",
            "STAFF_VLAN": "20",
            "GUEST_VLAN": "30",
            "IOT_VLAN": "40",
            "MGMT_SUBNET": "10.10.10.0/24",
            "STAFF_SUBNET": "10.10.20.0/24",
            "GUEST_SUBNET": "10.10.30.0/24",
            "IOT_SUBNET": "10.10.40.0/24",
            "MGMT_GATEWAY": "10.10.10.1",
            "STAFF_GATEWAY": "10.10.20.1",
            "GUEST_GATEWAY": "10.10.30.1",
            "IOT_GATEWAY": "10.10.40.1",
            "WIREGUARD_PORT": "13231",
            "DNS_PRIMARY": "1.1.1.1",
            "DNS_SECONDARY": "8.8.8.8",
            "COUNTRY": "Ukraine",
            "TIMEZONE": "Europe/Kyiv"
        },
        "config": """# model = hAP ax3
/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}" vlan-filtering=yes comment="VLAN-Aware Bridge"
/interface vlan
add interface="{{LAN_BRIDGE}}" name=vlan_mgmt vlan-id={{MGMT_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_staff vlan-id={{STAFF_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_guest vlan-id={{GUEST_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_iot vlan-id={{IOT_VLAN}}
/interface wireguard add name=wg_server listen-port={{WIREGUARD_PORT}} comment="WireGuard Server"
/interface wireguard peers add interface=wg_server public-key="PEER_PUBLIC_KEY_PLACEHOLDER" allowed-address=10.250.0.2/32 comment="Admin Mobile"
/interface bridge port
add bridge="{{LAN_BRIDGE}}" interface=ether2 pvid={{STAFF_VLAN}} comment="Staff port"
add bridge="{{LAN_BRIDGE}}" interface=ether3 pvid={{GUEST_VLAN}} comment="Guest port"
add bridge="{{LAN_BRIDGE}}" interface=ether4 pvid={{IOT_VLAN}} comment="IoT port"
/interface bridge vlan
add bridge="{{LAN_BRIDGE}}" tagged=bridge,ether2,ether3,ether4 vlan-ids={{MGMT_VLAN}},{{STAFF_VLAN}},{{GUEST_VLAN}},{{IOT_VLAN}}
/ip address
add address="{{MGMT_GATEWAY}}/24" interface=vlan_mgmt
add address="{{STAFF_GATEWAY}}/24" interface=vlan_staff
add address="{{GUEST_GATEWAY}}/24" interface=vlan_guest
add address="{{IOT_GATEWAY}}/24" interface=vlan_iot
add address="10.250.0.1/24" interface=wg_server
/ip pool
add name=pool_mgmt ranges="10.10.10.10-10.10.10.250"
add name=pool_staff ranges="10.10.20.10-10.10.20.250"
add name=pool_guest ranges="10.10.30.10-10.10.30.250"
add name=pool_iot ranges="10.10.40.10-10.10.40.250"
/ip dhcp-server
add name=dhcp_mgmt interface=vlan_mgmt address-pool=pool_mgmt disabled=no
add name=dhcp_staff interface=vlan_staff address-pool=pool_staff disabled=no
add name=dhcp_guest interface=vlan_guest address-pool=pool_guest disabled=no
add name=dhcp_iot interface=vlan_iot address-pool=pool_iot disabled=no
/ip dhcp-server network
add address="{{MGMT_SUBNET}}" gateway="{{MGMT_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
add address="{{STAFF_SUBNET}}" gateway="{{STAFF_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
add address="{{GUEST_SUBNET}}" gateway="{{GUEST_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
add address="{{IOT_SUBNET}}" gateway="{{IOT_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
/ip dhcp-client add interface="{{WAN_INTERFACE}}" disabled=no add-default-route=yes
/ip dns set servers="{{DNS_PRIMARY}},{{DNS_SECONDARY}}" allow-remote-requests=yes
/ip firewall filter
add chain=input action=accept connection-state=established,related comment="Accept established/related"
add chain=input action=drop connection-state=invalid comment="Drop invalid"
add chain=input action=accept protocol=icmp comment="Accept ICMP"
add chain=input action=accept in-interface=vlan_mgmt comment="Accept Mgmt VLAN"
add chain=input action=accept in-interface=wg_server comment="Accept Admin WG"
add chain=input action=drop dst-port=53 protocol=udp in-interface="{{WAN_INTERFACE}}" comment="Block WAN DNS"
add chain=input action=drop dst-port=53 protocol=tcp in-interface="{{WAN_INTERFACE}}" comment="Block WAN DNS"
add chain=input action=drop comment="Drop all other input"
add chain=forward action=fasttrack-connection connection-state=established,related comment="FastTrack"
add chain=forward action=accept connection-state=established,related comment="Accept established/related"
add chain=forward action=drop connection-state=invalid comment="Drop invalid"
add chain=forward action=accept in-interface=vlan_staff comment="Staff access to WAN"
add chain=forward action=accept in-interface=vlan_guest comment="Guest access to WAN"
add chain=forward action=accept in-interface=vlan_iot comment="IoT access to WAN"
add chain=forward action=accept in-interface=wg_server out-interface=vlan_mgmt comment="WG Admin access to Mgmt"
add chain=forward action=drop comment="Drop all other forwarding"
/ip firewall nat add chain=srcnat action=masquerade out-interface="{{WAN_INTERFACE}}"
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/system clock set time-zone-name="{{TIMEZONE}}"
"""
    },
    "smb_office": {
        "title": "SMB Office",
        "description": "Корпоративна мережа для малого офісу. Ізольовані VLAN, безпечний віддалений доступ, строгий Firewall.",
        "variables": {
            "SITE_NAME": "Office-Main",
            "WAN_INTERFACE": "ether1",
            "LAN_BRIDGE": "bridge",
            "MGMT_VLAN": "10",
            "STAFF_VLAN": "20",
            "GUEST_VLAN": "30",
            "IOT_VLAN": "40",
            "MGMT_SUBNET": "10.20.10.0/24",
            "STAFF_SUBNET": "10.20.20.0/24",
            "GUEST_SUBNET": "10.20.30.0/24",
            "IOT_SUBNET": "10.20.40.0/24",
            "MGMT_GATEWAY": "10.20.10.1",
            "STAFF_GATEWAY": "10.20.20.1",
            "GUEST_GATEWAY": "10.20.30.1",
            "IOT_GATEWAY": "10.20.40.1",
            "DNS_PRIMARY": "1.1.1.1",
            "DNS_SECONDARY": "8.8.8.8",
            "COUNTRY": "Ukraine",
            "TIMEZONE": "Europe/Kyiv"
        },
        "config": """# model = RB5009
/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}" vlan-filtering=yes comment="VLAN Filtering Bridge"
/interface vlan
add interface="{{LAN_BRIDGE}}" name=vlan_mgmt vlan-id={{MGMT_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_staff vlan-id={{STAFF_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_guest vlan-id={{GUEST_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_iot vlan-id={{IOT_VLAN}}
/interface list add name=LAN
/interface list add name=WAN
/interface list member
add interface=vlan_mgmt list=LAN
add interface=vlan_staff list=LAN
add interface=vlan_guest list=LAN
add interface=vlan_iot list=LAN
add interface="{{WAN_INTERFACE}}" list=WAN
/interface bridge port
add bridge="{{LAN_BRIDGE}}" interface=ether2 pvid={{MGMT_VLAN}} comment="Mgmt switch connection"
add bridge="{{LAN_BRIDGE}}" interface=ether3 pvid={{STAFF_VLAN}} comment="Staff port"
add bridge="{{LAN_BRIDGE}}" interface=ether4 pvid={{GUEST_VLAN}} comment="Guest port"
/interface bridge vlan
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}},ether2" untagged=ether3 vlan-ids={{STAFF_VLAN}}
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}},ether2" untagged=ether4 vlan-ids={{GUEST_VLAN}}
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}},ether2" vlan-ids={{MGMT_VLAN}},{{IOT_VLAN}}
/ip address
add address="{{MGMT_GATEWAY}}/24" interface=vlan_mgmt
add address="{{STAFF_GATEWAY}}/24" interface=vlan_staff
add address="{{GUEST_GATEWAY}}/24" interface=vlan_guest
add address="{{IOT_GATEWAY}}/24" interface=vlan_iot
/ip pool
add name=pool_mgmt ranges="10.20.10.50-10.20.10.250"
add name=pool_staff ranges="10.20.20.50-10.20.20.250"
add name=pool_guest ranges="10.20.30.50-10.20.30.250"
add name=pool_iot ranges="10.20.40.50-10.20.40.250"
/ip dhcp-server
add name=dhcp_mgmt interface=vlan_mgmt address-pool=pool_mgmt disabled=no
add name=dhcp_staff interface=vlan_staff address-pool=pool_staff disabled=no
add name=dhcp_guest interface=vlan_guest address-pool=pool_guest disabled=no
add name=dhcp_iot interface=vlan_iot address-pool=pool_iot disabled=no
/ip dhcp-server network
add address="{{MGMT_SUBNET}}" gateway="{{MGMT_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
add address="{{STAFF_SUBNET}}" gateway="{{STAFF_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
add address="{{GUEST_SUBNET}}" gateway="{{GUEST_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
add address="{{IOT_SUBNET}}" gateway="{{IOT_GATEWAY}}" dns-server="{{DNS_PRIMARY}}"
/ip dhcp-client add interface="{{WAN_INTERFACE}}" disabled=no add-default-route=yes
/ip dns set servers="{{DNS_PRIMARY}},{{DNS_SECONDARY}}" allow-remote-requests=yes
/ip firewall filter
add chain=input action=accept connection-state=established,related comment="Accept established/related"
add chain=input action=drop connection-state=invalid comment="Drop invalid"
add chain=input action=accept protocol=icmp comment="Accept ICMP"
add chain=input action=accept in-interface=vlan_mgmt comment="Accept Admin Mgmt"
add chain=input action=drop dst-port=53 protocol=udp in-interface-list=WAN comment="Block DNS from WAN"
add chain=input action=drop dst-port=53 protocol=tcp in-interface-list=WAN comment="Block DNS from WAN"
add chain=input action=drop comment="Drop all other input"
add chain=forward action=fasttrack-connection connection-state=established,related comment="FastTrack"
add chain=forward action=accept connection-state=established,related comment="Accept established/related"
add chain=forward action=drop connection-state=invalid comment="Drop invalid"
add chain=forward action=accept in-interface=vlan_staff out-interface-list=WAN comment="Staff to WAN"
add chain=forward action=accept in-interface=vlan_guest out-interface-list=WAN comment="Guest to WAN"
add chain=forward action=accept in-interface=vlan_iot out-interface-list=WAN comment="IoT to WAN"
add chain=forward action=drop comment="Drop all other forwarding"
/ip firewall nat add chain=srcnat action=masquerade out-interface-list=WAN
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=yes
/ip service set api-ssl disabled=yes
/tool mac-server mac-winbox set allowed-interface-list=none
/ip neighbor discovery-settings set discover-interface-list=none
/system clock set time-zone-name="{{TIMEZONE}}"
"""
    },
    "enterprise_branch": {
        "title": "Enterprise Branch",
        "description": "Конфігурація філіалу підприємства: транкові порти, OSPF маршрутизація, SNMP, логування на Syslog.",
        "variables": {
            "SITE_NAME": "Branch-HQ",
            "WAN_INTERFACE": "ether1",
            "LAN_BRIDGE": "bridge",
            "MGMT_VLAN": "10",
            "STAFF_VLAN": "20",
            "MGMT_SUBNET": "10.100.10.0/24",
            "STAFF_SUBNET": "10.100.20.0/24",
            "MGMT_GATEWAY": "10.100.10.1",
            "STAFF_GATEWAY": "10.100.20.1",
            "DNS_PRIMARY": "10.100.10.10",
            "DNS_SECONDARY": "8.8.8.8",
            "COUNTRY": "Ukraine",
            "TIMEZONE": "Europe/Kyiv"
        },
        "config": """# model = CCR2004
/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}" vlan-filtering=yes
/interface vlan
add interface="{{LAN_BRIDGE}}" name=vlan_mgmt vlan-id={{MGMT_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_staff vlan-id={{STAFF_VLAN}}
/interface list add name=LAN
/interface list add name=WAN
/interface list member
add interface=vlan_mgmt list=LAN
add interface=vlan_staff list=LAN
add interface="{{WAN_INTERFACE}}" list=WAN
/interface bridge port
add bridge="{{LAN_BRIDGE}}" interface=ether2 comment="VLAN Trunk Port to core switch"
add bridge="{{LAN_BRIDGE}}" interface=ether3 comment="VLAN Trunk Port to server rack"
/interface bridge vlan
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}},ether2,ether3" vlan-ids={{MGMT_VLAN}},{{STAFF_VLAN}}
/ip address
add address="{{MGMT_GATEWAY}}/24" interface=vlan_mgmt
add address="{{STAFF_GATEWAY}}/24" interface=vlan_staff
/ip pool
add name=pool_staff ranges="10.100.20.10-10.100.20.254"
/ip dhcp-server
add name=dhcp_staff interface=vlan_staff address-pool=pool_staff disabled=no
/ip dhcp-server network
add address="{{STAFF_SUBNET}}" gateway="{{STAFF_GATEWAY}}" dns-server="{{DNS_PRIMARY}},{{DNS_SECONDARY}}"
/ip dhcp-client add interface="{{WAN_INTERFACE}}" disabled=no add-default-route=yes
/routing ospf instance add name=ospf-inst-1 router-id={{MGMT_GATEWAY}}
/routing ospf area add name=area-backbone instance=ospf-inst-1 area-id=0.0.0.0
/routing ospf interface-template add area=area-backbone interfaces=vlan_mgmt type=ptp
/ip dns set servers="{{DNS_PRIMARY}},{{DNS_SECONDARY}}" allow-remote-requests=no
/snmp set enabled=yes trap-version=2 contact="admin@mycompany.com"
/snmp community add name=company-monitoring addresses=10.100.10.0/24 read-access=yes
/system logging action add name=syslog-server target=remote remote=10.100.10.25 remote-port=514
/system logging add action=syslog-server topics=info,warning,error
/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid
add chain=input action=accept protocol=icmp
add chain=input action=accept in-interface=vlan_mgmt
add chain=input action=drop comment="Drop other input"
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid
add chain=forward action=accept in-interface=vlan_staff out-interface-list=WAN
add chain=forward action=drop comment="Drop other forward"
/ip firewall nat add chain=srcnat action=masquerade out-interface-list=WAN
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=yes
/ip service set winbox port=8291 address=10.100.10.0/24
/system clock set time-zone-name="{{TIMEZONE}}"
"""
    },
    "capsman_controller": {
        "title": "CAPsMAN Controller",
        "description": "Налаштування контролера точок доступу CAPsMAN (v7) для централізованого керування WiFi.",
        "variables": {
            "SITE_NAME": "CAPsMAN-HQ",
            "LAN_BRIDGE": "bridge",
            "STAFF_VLAN": "20",
            "GUEST_VLAN": "30",
            "COUNTRY": "Ukraine"
        },
        "config": """/system identity set name="{{SITE_NAME}}"
/interface wifi capsman set enabled=yes require-peer-certificate=no
/interface wifi security
add name=sec_staff authentication-types=wpa2-psk,wpa3-psk passphrase="StaffSecurePass123!"
add name=sec_guest authentication-types=wpa2-psk passphrase="GuestWiFiPass!"
/interface wifi configuration
add name=cfg_staff ssid="Office-Staff" security=sec_staff datapath.bridge="{{LAN_BRIDGE}}" datapath.vlan-id={{STAFF_VLAN}} country="{{COUNTRY}}"
add name=cfg_guest ssid="Office-Guest" security=sec_guest datapath.bridge="{{LAN_BRIDGE}}" datapath.vlan-id={{GUEST_VLAN}} country="{{COUNTRY}}"
/interface wifi provisioning
add action=create-dynamic-enabled master-configuration=cfg_staff slave-configurations=cfg_guest supported-bands=2ghz,5ghz
"""
    },
    "caps_device": {
        "title": "CAP Device",
        "description": "Конфігурація точки доступу (CAP) для роботи під управлінням контролера CAPsMAN.",
        "variables": {
            "SITE_NAME": "AP-Branch-01",
            "LAN_BRIDGE": "bridge"
        },
        "config": """/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}" vlan-filtering=yes
/interface bridge port
add bridge="{{LAN_BRIDGE}}" interface=ether1 comment="Trunk port connecting to switch"
/interface wifi datapath add name=dp-cap bridge="{{LAN_BRIDGE}}"
/interface wifi cap set enabled=yes discovery-interfaces="{{LAN_BRIDGE}}" interfaces=wifi1,wifi2 datapath=dp-cap
"""
    },
    "guest_wifi": {
        "title": "Guest WiFi",
        "description": "Спеціальна конфігурація гостьової WiFi мережі: ізольована маршрутизація, обмеження швидкості клієнтів.",
        "variables": {
            "SITE_NAME": "Router-GuestNet",
            "LAN_BRIDGE": "bridge",
            "GUEST_VLAN": "30",
            "GUEST_SUBNET": "192.168.130.0/24",
            "GUEST_GATEWAY": "192.168.130.1"
        },
        "config": """/interface vlan add interface="{{LAN_BRIDGE}}" name=vlan_guest vlan-id={{GUEST_VLAN}}
/ip address add address="{{GUEST_GATEWAY}}/24" interface=vlan_guest
/ip pool add name=pool_guest ranges="192.168.130.10-192.168.130.254"
/ip dhcp-server add name=dhcp_guest interface=vlan_guest address-pool=pool_guest disabled=no
/ip dhcp-server network add address="{{GUEST_SUBNET}}" gateway="{{GUEST_GATEWAY}}" dns-server=8.8.8.8
/queue simple add name="Limit-Guest-WiFi" target=vlan_guest max-limit=10M/10M comment="Limit guest upload/download speed"
/ip firewall filter
add chain=forward action=drop in-interface=vlan_guest out-interface=!ether1 comment="Isolate guest from other LAN interfaces"
"""
    },
    "iot_network": {
        "title": "IoT Network",
        "description": "Конфігурація для розумних пристроїв та сенсорів (IoT): закритий доступ до основної мережі та інтерфейсу керування.",
        "variables": {
            "LAN_BRIDGE": "bridge",
            "IOT_VLAN": "40",
            "IOT_SUBNET": "10.40.0.0/24",
            "IOT_GATEWAY": "10.40.0.1"
        },
        "config": """/interface vlan add interface="{{LAN_BRIDGE}}" name=vlan_iot vlan-id={{IOT_VLAN}}
/ip address add address="{{IOT_GATEWAY}}/24" interface=vlan_iot
/ip pool add name=pool_iot ranges="10.40.0.10-10.40.0.254"
/ip dhcp-server add name=dhcp_iot interface=vlan_iot address-pool=pool_iot disabled=no
/ip dhcp-server network add address="{{IOT_SUBNET}}" gateway="{{IOT_GATEWAY}}" dns-server=8.8.8.8
/ip firewall filter
add chain=forward action=drop in-interface=vlan_iot out-interface=vlan_mgmt comment="Block IoT to Mgmt"
add chain=forward action=drop in-interface=vlan_iot out-interface=vlan_staff comment="Block IoT to Staff"
"""
    },
    "cctv_network": {
        "title": "CCTV Network",
        "description": "Конфігурація відеонагляду (CCTV): ізоляція камер, обмежений вихід в інтернет, прокидання портів для відеореєстратора.",
        "variables": {
            "LAN_BRIDGE": "bridge",
            "CCTV_VLAN": "50",
            "CCTV_SUBNET": "10.50.0.0/24",
            "CCTV_GATEWAY": "10.50.0.1",
            "WAN_INTERFACE": "ether1",
            "NVR_IP": "10.50.0.10"
        },
        "config": """/interface vlan add interface="{{LAN_BRIDGE}}" name=vlan_cctv vlan-id={{CCTV_VLAN}}
/ip address add address="{{CCTV_GATEWAY}}/24" interface=vlan_cctv
/ip pool add name=pool_cctv ranges="10.50.0.20-10.50.0.254"
/ip dhcp-server add name=dhcp_cctv interface=vlan_cctv address-pool=pool_cctv disabled=no
/ip dhcp-server network add address="{{CCTV_SUBNET}}" gateway="{{CCTV_GATEWAY}}" dns-server=8.8.8.8
/ip firewall filter
add chain=forward action=drop in-interface=vlan_cctv out-interface-list=!WAN comment="Block CCTV to local LAN networks"
add chain=forward action=drop in-interface=vlan_cctv out-interface="{{WAN_INTERFACE}}" src-address-list=!allowed_cctv_wan comment="Block IP cameras WAN access (except NVR)"
/ip firewall address-list add list=allowed_cctv_wan address="{{NVR_IP}}"
/ip firewall nat add chain=dstnat action=dst-nat to-addresses="{{NVR_IP}}" to-ports=8000 protocol=tcp dst-port=8000 in-interface="{{WAN_INTERFACE}}" comment="Port forwarding for NVR app"
"""
    },
    "multiwan": {
        "title": "MultiWAN",
        "description": "Підключення до двох провайдерів (WAN1 та WAN2). PCC балансування та автоматичне резервування.",
        "variables": {
            "WAN1_INTERFACE": "ether1",
            "WAN2_INTERFACE": "ether2",
            "WAN1_GATEWAY": "192.168.1.1",
            "WAN2_GATEWAY": "192.168.2.1",
            "LAN_BRIDGE": "bridge",
            "STAFF_SUBNET": "192.168.88.0/24"
        },
        "config": """/ip route
add dst-address=0.0.0.0/0 gateway="{{WAN1_GATEWAY}}" routing-table=main distance=1 check-gateway=ping
add dst-address=0.0.0.0/0 gateway="{{WAN2_GATEWAY}}" routing-table=main distance=2 check-gateway=ping
/routing table add name=to_WAN1 fib
/routing table add name=to_WAN2 fib
/ip route
add dst-address=0.0.0.0/0 gateway="{{WAN1_GATEWAY}}" routing-table=to_WAN1
add dst-address=0.0.0.0/0 gateway="{{WAN2_GATEWAY}}" routing-table=to_WAN2
/ip firewall mangle
add chain=prerouting dst-address-type=!local in-interface="{{LAN_BRIDGE}}" connection-state=new \\
    per-connection-classifier=both-addresses-and-ports:2/0 action=mark-connection new-connection-mark=WAN1_conn passthrough=yes
add chain=prerouting dst-address-type=!local in-interface="{{LAN_BRIDGE}}" connection-state=new \\
    per-connection-classifier=both-addresses-and-ports:2/1 action=mark-connection new-connection-mark=WAN2_conn passthrough=yes
add chain=prerouting in-interface="{{LAN_BRIDGE}}" connection-mark=WAN1_conn action=mark-routing new-routing-mark=to_WAN1 passthrough=no
add chain=prerouting in-interface="{{LAN_BRIDGE}}" connection-mark=WAN2_conn action=mark-routing new-routing-mark=to_WAN2 passthrough=no
/ip firewall nat
add chain=srcnat action=masquerade out-interface="{{WAN1_INTERFACE}}"
add chain=srcnat action=masquerade out-interface="{{WAN2_INTERFACE}}"
"""
    },
    "lte_backup": {
        "title": "LTE Backup",
        "description": "Використання вбудованого модему або USB-LTE як резервного каналу зв'язку за допомогою Netwatch.",
        "variables": {
            "WAN_INTERFACE": "ether1",
            "LTE_INTERFACE": "lte1",
            "WAN_GATEWAY": "192.168.1.1"
        },
        "config": """/ip route
add dst-address=0.0.0.0/0 gateway="{{WAN_GATEWAY}}" distance=1 comment="Primary WAN"
add dst-address=0.0.0.0/0 gateway="{{LTE_INTERFACE}}" distance=5 comment="LTE Backup"
/tool netwatch
add host=8.8.8.8 interval=10s timeout=2s \\
    up-script="/ip route enable [find comment=\\"Primary WAN\\"]" \\
    down-script="/ip route disable [find comment=\\"Primary WAN\\"]"
"""
    },
    "wireguard_hub": {
        "title": "WireGuard Hub",
        "description": "Налаштування WireGuard концентратора (Hub) для об'єднання віддалених точок та мобільних клієнтів.",
        "variables": {
            "WIREGUARD_PORT": "13231",
            "WIREGUARD_SUBNET": "10.250.0.0/24",
            "WIREGUARD_IP": "10.250.0.1",
            "WAN_INTERFACE": "ether1"
        },
        "config": """/interface wireguard add name=wg_hub listen-port={{WIREGUARD_PORT}} comment="WireGuard Server Hub"
/ip address add address="{{WIREGUARD_IP}}/24" interface=wg_hub
/ip firewall filter
add chain=input action=accept protocol=udp dst-port={{WIREGUARD_PORT}} comment="Allow WireGuard Port"
add chain=input action=accept in-interface=wg_hub comment="Allow WireGuard Traffic to Router"
add chain=forward action=accept in-interface=wg_hub comment="Allow Routed WG traffic"
/ip firewall nat add chain=srcnat action=masquerade src-address="{{WIREGUARD_SUBNET}}" out-interface="{{WAN_INTERFACE}}"
"""
    },
    "wireguard_spoke": {
        "title": "WireGuard Spoke",
        "description": "Підключення філіалу (Spoke) до центрального WireGuard Hub. Маршрутизація трафіку в офіс.",
        "variables": {
            "HUB_ENDPOINT": "198.51.100.10",
            "WIREGUARD_PORT": "13231",
            "SPOKE_IP": "10.250.0.5",
            "HUB_PUBLIC_KEY": "KEY_HUB_PLACEHOLDER",
            "HUB_LAN_SUBNET": "10.100.0.0/16"
        },
        "config": """/interface wireguard add name=wg_spoke listen-port=13232
/ip address add address="{{SPOKE_IP}}/24" interface=wg_spoke
/interface wireguard peers add interface=wg_spoke endpoint-address="{{HUB_ENDPOINT}}" endpoint-port={{WIREGUARD_PORT}} \\
    public-key="{{HUB_PUBLIC_KEY}}" allowed-address="10.250.0.0/24,{{HUB_LAN_SUBNET}}" persistent-keepalive=25s
/ip route add dst-address="{{HUB_LAN_SUBNET}}" gateway=wg_spoke comment="Route to Hub LAN via WG"
"""
    },
    "vlan_segmented_network": {
        "title": "VLAN Segmented Network",
        "description": "Повна корпоративна мережа з розділенням на VLAN: Mgmt, Staff, Guest, CCTV, IoT. Фільтрація трафіку на Bridge.",
        "variables": {
            "SITE_NAME": "VLAN-Core",
            "LAN_BRIDGE": "bridge",
            "MGMT_VLAN": "10",
            "STAFF_VLAN": "20",
            "GUEST_VLAN": "30",
            "CCTV_VLAN": "50",
            "IOT_VLAN": "40",
            "MGMT_GATEWAY": "10.99.10.1",
            "STAFF_GATEWAY": "10.99.20.1",
            "GUEST_GATEWAY": "10.99.30.1",
            "CCTV_GATEWAY": "10.99.50.1",
            "IOT_GATEWAY": "10.99.40.1"
        },
        "config": """/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}" vlan-filtering=yes
/interface vlan
add interface="{{LAN_BRIDGE}}" name=vlan_mgmt vlan-id={{MGMT_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_staff vlan-id={{STAFF_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_guest vlan-id={{GUEST_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_cctv vlan-id={{CCTV_VLAN}}
add interface="{{LAN_BRIDGE}}" name=vlan_iot vlan-id={{IOT_VLAN}}
/interface bridge port
add bridge="{{LAN_BRIDGE}}" interface=ether2 pvid={{STAFF_VLAN}}
add bridge="{{LAN_BRIDGE}}" interface=ether3 pvid={{GUEST_VLAN}}
add bridge="{{LAN_BRIDGE}}" interface=ether4 pvid={{CCTV_VLAN}}
add bridge="{{LAN_BRIDGE}}" interface=ether5 pvid={{IOT_VLAN}}
/interface bridge vlan
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}}" untagged=ether2 vlan-ids={{STAFF_VLAN}}
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}}" untagged=ether3 vlan-ids={{GUEST_VLAN}}
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}}" untagged=ether4 vlan-ids={{CCTV_VLAN}}
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}}" untagged=ether5 vlan-ids={{IOT_VLAN}}
add bridge="{{LAN_BRIDGE}}" tagged="{{LAN_BRIDGE}}" vlan-ids={{MGMT_VLAN}}
/ip address
add address="{{MGMT_GATEWAY}}/24" interface=vlan_mgmt
add address="{{STAFF_GATEWAY}}/24" interface=vlan_staff
add address="{{GUEST_GATEWAY}}/24" interface=vlan_guest
add address="{{CCTV_GATEWAY}}/24" interface=vlan_cctv
add address="{{IOT_GATEWAY}}/24" interface=vlan_iot
"""
    },
    "isp_cpe": {
        "title": "ISP CPE",
        "description": "Налаштування роутера для домашнього/офісного підключення по PPPoE. NAT, Firewall та DHCP клієнт.",
        "variables": {
            "SITE_NAME": "ISP-Router",
            "WAN_INTERFACE": "ether1",
            "LAN_BRIDGE": "bridge",
            "PPPOE_USER": "myusername",
            "PPPOE_PASS": "mypassword123",
            "LAN_IP": "192.168.1.1"
        },
        "config": """/system identity set name="{{SITE_NAME}}"
/interface bridge add name="{{LAN_BRIDGE}}"
/interface pppoe-client add name=pppoe-out1 interface="{{WAN_INTERFACE}}" user="{{PPPOE_USER}}" password="{{PPPOE_PASS}}" add-default-route=yes use-peer-dns=yes disabled=no
/ip address add address="{{LAN_IP}}/24" interface="{{LAN_BRIDGE}}"
/ip pool add name=dhcp_pool ranges=192.168.1.10-192.168.1.254
/ip dhcp-server add name=dhcp_lan interface="{{LAN_BRIDGE}}" address-pool=dhcp_pool disabled=no
/ip dhcp-server network add address=192.168.1.0/24 gateway="{{LAN_IP}}" dns-server="{{LAN_IP}}"
/ip firewall nat add chain=srcnat action=masquerade out-interface=pppoe-out1
/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid
add chain=input action=accept protocol=icmp
add chain=input action=accept in-interface="{{LAN_BRIDGE}}"
add chain=input action=drop in-interface=pppoe-out1
add chain=forward action=fasttrack-connection connection-state=established,related
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid
add chain=forward action=accept in-interface="{{LAN_BRIDGE}}" out-interface=pppoe-out1
add chain=forward action=drop connection-nat-state=!dstnat
"""
    },
    "datacenter_edge": {
        "title": "Data Center Edge",
        "description": "Прикордонний роутер датацентру: OSPF/BGP маршрутизація, обмеження на кількість з'єднань, SSH фільтрація.",
        "variables": {
            "SITE_NAME": "DC-Edge-01",
            "WAN_INTERFACE": "sfp-sfpplus1",
            "LAN_INTERFACE": "sfp-sfpplus2",
            "PUBLIC_IP": "203.0.113.5",
            "GATEWAY_IP": "203.0.113.1",
            "AS_NUMBER": "65530",
            "PEER_AS": "65000",
            "PEER_IP": "203.0.113.2"
        },
        "config": """/system identity set name="{{SITE_NAME}}"
/ip address
add address="{{PUBLIC_IP}}/30" interface="{{WAN_INTERFACE}}"
/ip route
add dst-address=0.0.0.0/0 gateway="{{GATEWAY_IP}}" check-gateway=ping
/routing bgp connection
add name=bgp-to-isp local.role=ebgp local.as={{AS_NUMBER}} remote.as={{PEER_AS}} remote.address="{{PEER_IP}}" connect=yes
/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid
add chain=input action=accept protocol=icmp
add chain=input action=accept src-address-list=allowed_admins protocol=tcp dst-port=22 comment="Restricted SSH"
add chain=input action=drop protocol=tcp dst-port=22
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid
add chain=forward action=drop protocol=tcp connection-limit=100,32 connection-state=new comment="TCP Connection Limit per client"
/ip firewall address-list
add list=allowed_admins address=198.51.100.0/24
add list=allowed_admins address=203.0.113.5
"""
    },
    "core": {
        "title": "CORE Enterprise Router",
        "description": "Шаблон ядра мережі для RB5009 з двома провайдерами (PCC балансування), OVPN тунелем, WiFi (CAPsMAN), ZeroTier, syslog логуванням та автоматичним резервуванням каналів.",
        "variables": {
            "SITE_NAME": "MT-RB5009UPr-AV2-TKP",
            "WAN1": "ether1",
            "WAN2": "ether2",
            "LAN_BRIDGE": "bridge-work",
            "GUEST_BRIDGE": "bridge-guest",
            "WORK_GATEWAY": "10.16.132.1",
            "WORK_NETWORK": "10.16.132.0/24",
            "WORK_NETWORK_BASE": "10.16.132.0",
            "GUEST_GATEWAY": "192.168.132.1",
            "GUEST_NETWORK": "192.168.132.0/24",
            "GUEST_NETWORK_BASE": "192.168.132.0",
            "WORK_POOL_RANGE": "10.16.132.50-10.16.132.250",
            "GUEST_POOL_RANGE": "192.168.132.50-192.168.132.250",
            "WORK_SSID": "ASUS-2525",
            "WORK_SSID_WIFI": "ASUS_2525",
            "GUEST_SSID": "COFFEE_HOUSE",
            "GUEST_SSID_QUOTED": "COFFEE HOUSE",
            "WORK_WIFI_PASSWORD": "WORK_PASSWORD_PLACEHOLDER",
            "GUEST_WIFI_PASSWORD": "GUEST_PASSWORD_PLACEHOLDER",
            "ZEROTIER_NETWORK_ID": "ZT_NETWORK_ID_PLACEHOLDER",
            "OVPN_SERVER": "ovpn.example.com",
            "OVPN_USER": "ovpn_user",
            "OVPN_PASSWORD": "OVPN_PASSWORD_PLACEHOLDER",
            "GRAYLOG_SERVER": "10.16.250.111",
            "LOG_SERVER": "10.0.1.120",
            "TFTP_SERVER": "10.16.250.3"
        },
        "config": """/caps-man channel
add band=2ghz-onlyn control-channel-width=20mhz name=channel2 \\
    skip-dfs-channels=no tx-power=20
add band=5ghz-n/ac control-channel-width=20mhz name=channel5 \\
    skip-dfs-channels=no tx-power=22
/interface bridge
add name={{GUEST_BRIDGE}}
add name={{LAN_BRIDGE}}
/interface ethernet
set [ find default-name={{WAN1}} ] comment=ISP1 l2mtu=1514
set [ find default-name={{WAN2}} ] comment=ISP2 l2mtu=1514
set [ find default-name=ether3 ] l2mtu=1514
set [ find default-name=ether4 ] l2mtu=1514
set [ find default-name=ether5 ] l2mtu=1514
set [ find default-name=ether6 ] l2mtu=1514
set [ find default-name=ether7 ] l2mtu=1514
set [ find default-name=ether8 ] l2mtu=1514
set [ find default-name=sfp-sfpplus1 ] l2mtu=1514
/interface ovpn-client
add certificate=i260520007 cipher=aes256-cbc connect-to={{OVPN_SERVER}} \\
    mac-address=FE:4A:FB:A1:E0:24 name=warcloud password={{OVPN_PASSWORD}} \\
    port=4327 route-nopull=yes use-peer-dns=no user={{OVPN_USER}} \\
    verify-server-certificate=yes
/interface vlan
add interface={{LAN_BRIDGE}} name=vlan10-guest vlan-id=10
/caps-man datapath
add bridge={{LAN_BRIDGE}} client-to-client-forwarding=yes local-forwarding=no \\
    name=local
add bridge={{GUEST_BRIDGE}} client-to-client-forwarding=yes local-forwarding=no \\
    name=wifi
/caps-man security
add authentication-types=wpa2-psk encryption=aes-ccm group-encryption=aes-ccm \\
    group-key-update=10m name=local passphrase={{WORK_WIFI_PASSWORD}}
add authentication-types=wpa2-psk encryption=aes-ccm group-encryption=aes-ccm \\
    group-key-update=10m name=wifi passphrase={{GUEST_WIFI_PASSWORD}}
/caps-man configuration
add channel=channel2 country=no_country_set datapath=wifi mode=ap name=\\
    wifi-cfg2 rx-chains=0,1,2,3 security=wifi ssid="{{GUEST_SSID_QUOTED}}" tx-chains=\\
    0,1,2,3
add channel=channel2 country=no_country_set datapath=local hide-ssid=yes mode=\\
    ap name=local-cfg2 rx-chains=0,1,2,3 security=local ssid={{WORK_SSID}} \\
    tx-chains=0,1,2,3
add channel=channel5 country=no_country_set datapath=wifi mode=ap name=\\
    wifi-cfg5 rx-chains=0,1,2,3 security=wifi ssid="{{GUEST_SSID_QUOTED}}" tx-chains=\\
    0,1,2,3
add channel=channel5 country=no_country_set datapath=local hide-ssid=yes mode=\\
    ap name=local-cfg5 rx-chains=0,1,2,3 security=local ssid={{WORK_SSID}} \\
    tx-chains=0,1,2,3
/interface list
add name=WAN
add name=LAN
add name=OVPN
/interface wifi channel
add band=2ghz-ax disabled=no frequency=2462 name=channel2 width=20mhz
add band=5ghz-ax disabled=no frequency=5240 name=channel5 width=20/40mhz
/interface wifi datapath
add bridge={{LAN_BRIDGE}} disabled=no name=local
add bridge={{GUEST_BRIDGE}} client-isolation=no disabled=no name=wifi vlan-id=10
/interface wifi security
add authentication-types=wpa2-psk disabled=no ft=yes ft-over-ds=yes name=local \\
    passphrase={{WORK_WIFI_PASSWORD}}
add authentication-types=wpa2-psk disabled=no ft=yes ft-over-ds=yes name=wifi \\
    passphrase={{GUEST_WIFI_PASSWORD}}
/interface wifi configuration
add channel=channel2 country="United States" datapath=local disabled=no \\
    hide-ssid=yes mode=ap name=cfg2-local security=local ssid={{WORK_SSID_WIFI}} \\
    tx-power=14
add channel=channel5 country="United States" datapath=local disabled=no \\
    hide-ssid=yes mode=ap name=cfg5-local security=local ssid={{WORK_SSID_WIFI}} \\
    tx-power=22
add channel=channel5 country="United States" datapath=wifi \\
    datapath.client-isolation=yes disabled=no mode=ap name=cfg5-wifi security=\\
    wifi ssid={{GUEST_SSID}} tx-power=22
add channel=channel2 country="United States" datapath=wifi \\
    datapath.client-isolation=yes disabled=no hide-ssid=no mode=ap name=\\
    cfg2-wifi security=wifi ssid={{GUEST_SSID}} tx-power=14
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip dhcp-server option
add code=150 name=tftp150 value="'{{TFTP_SERVER}}'"
add code=66 name=tftp66 value="'{{TFTP_SERVER}}'"
/ip pool
add name=work-pool ranges={{WORK_POOL_RANGE}}
add name=guest-pool ranges={{GUEST_POOL_RANGE}}
/ip dhcp-server
add address-pool=work-pool interface={{LAN_BRIDGE}} lease-time=1h name=dhcp-work
add address-pool=guest-pool interface={{GUEST_BRIDGE}} lease-time=1h name=\\
    dhcp-guest
/routing table
add fib name=to_ISP1
add fib name=to_ISP2
/system logging action
set 3 remote={{LOG_SERVER}} src-address=10.193.134.204
add name=graylog remote={{GRAYLOG_SERVER}} remote-port=1514 target=remote
/system script
add dont-require-permissions=yes name=keep_conn_quality owner=admin policy=\\
    read,write,policy,test source=":local interface1 \\"{{WAN1}}\\"\\r\\
    \\n:local interface2 \\"{{WAN2}}\\"\\r\\
    \\n:local pingTargets1 {\\"1.1.1.1\\"; \\"8.8.8.8\\"}\\r\\
    \\n:local pingTargets2 {\\"1.0.0.1\\"; \\"8.8.4.4\\"}\\r\\
    \\n:local maxPacketLoss 4\\r\\
    \\n:local checkPacketLoss do={\\r\\
    \\n    :local interface \\$1\\r\\
    \\n    :local target \\$2\\r\\
    \\n    :local count 5\\r\\
    \\n    :local success [/tool ping \\$target interface=\\$interface count=\\$cou\\
    nt]\\r\\
    \\n    :return (\\$count - \\$success)\\r\\
    \\n}\\r\\
    \\n:local allTargetsLoss1 true\\r\\
    \\n:local isIfaceEnabled1 true\\r\\
    \\n:foreach target in=\\$pingTargets1 do={\\r\\
    \\n    :if ([/interface get [find name=\\$interface1] running] = false) do={\\
    \\r\\
    \\n        :if (isIfaceEnabled1 = true) do={\\r\\
    \\n            :log warning \\"ISP1 Interface \\$interface1 is not running!\\"\\
    \\r\\
    \\n            :set isIfaceEnabled1 false\\r\\
    \\n        }\\r\\
    \\n    } else {\\r\\
    \\n        :local loss1 [\\$checkPacketLoss \\$interface1 \\$target]\\r\\
    \\n        :if (\\$loss1 < \\$maxPacketLoss) do={\\r\\
    \\n            :set allTargetsLoss1 false\\r\\
    \\n        }\\r\\
    \\n    }\\r\\
    \\n}\\r\\
    \\n:foreach i1 in=[/ip route find comment=\\"ISP1\\"] do={\\r\\
    \\n    :if (\\$allTargetsLoss1) do={\\r\\
    \\n        :if ([/ip route get \\$i1 disabled] = false) do={\\r\\
    \\n            :log warning \\"ISP1 disabled due to packet loss to all target\\
    s on \\$interface1\\"\\r\\
    \\n            /ip route set \\$i1 disabled=yes\\r\\
    \\n            /ip firewall mangle disable [find comment=\\"via ISP1 only\\"]\\
    \\r\\
    \\n#            /ip firewall mangle disable [find comment=\\"PCC: new LAN to \\
    WAN connections for ISP1_conn\\"]\\r\\
    \\n            :do {\\r\\
    \\n                /ip firewall connection remove [find connection-mark=\\"IS\\
    P1_conn\\"]\\r\\
    \\n            } on-error={\\r\\
    \\n                :log warning \\"Connection no more exist!\\"\\
    \\r\\
    \\n            }\\r\\
    \\n            /ip dns cache flush\\r\\
    \\n        }\\r\\
    \\n    } else {\\r\\
    \\n        :if ([/ip route get \\$i1 disabled] = true) do={\\r\\
    \\n            :log info \\"ISP1 enabled, acceptable packet loss on \\$interfa\\
    ce1\\"\\r\\
    \\n            /ip route set \\$i1 disabled=no\\r\\
    \\n            /ip firewall mangle enable [find comment=\\"via ISP1 only\\"]\\r\\
    \\n#            /ip firewall mangle enable [find comment=\\"PCC: new LAN to W\\
    AN connections for ISP1_conn\\"]\\r\\
    \\n        }\\r\\
    \\n    }\\r\\
    \\n}\\r\\
    \\n:local allTargetsLoss2 true\\r\\
    \\n:local isIfaceEnabled2 true\\r\\
    \\n:foreach target in=\\$pingTargets2 do={\\r\\
    \\n    :if ([/interface get [find name=\\$interface2] running] = false) do={\\
    \\r\\
    \\n        :if (isIfaceEnabled2 = true) do={\\r\\
    \\n            :log warning \\"ISP2 Interface \\$interface2 is not running!\\"\\
    \\r\\
    \\n            :set isIfaceEnabled2 false\\r\\
    \\n        }\\r\\
    \\n    } else {\\r\\
    \\n        :local loss2 [\\$checkPacketLoss \\$interface2 \\$target]\\r\\
    \\n        :if (\\$loss2 < \\$maxPacketLoss) do={\\r\\
    \\n            :set allTargetsLoss2 false\\r\\
    \\n        }\\r\\
    \\n    }\\r\\
    \\n}\\r\\
    \\n:foreach i2 in=[/ip route find comment=\\"ISP2\\"] do={\\r\\
    \\n    :if (\\$allTargetsLoss2) do={\\r\\
    \\n        :if ([/ip route get \\$i2 disabled] = false) do={\\r\\
    \\n            :log warning \\"ISP2 disabled due to packet loss to all target\\
    s on \\$interface2\\"\\r\\
    \\n            /ip route set \\$i2 disabled=yes\\r\\
    \\n            /ip firewall mangle disable [find comment=\\"via ISP2 only\\"]\\
    \\r\\
    \\n#            /ip firewall mangle disable [find comment=\\"PCC: new LAN to \\
    WAN connections for ISP2_conn\\"]\\r\\
    \\n            :do {\\r\\
    \\n                /ip firewall connection remove [find connection-mark=\\"IS\\
    P2_conn\\"]\\r\\
    \\n            } on-error={\\r\\
    \\n                :log warning \\"Connection no more exist!\\"\\
    \\r\\
    \\n            }\\r\\
    \\n            /ip dns cache flush\\r\\
    \\n        }\\r\\
    \\n    } else {\\r\\
    \\n        :if ([/ip route get \\$i2 disabled] = true) do={\\r\\
    \\n            :log info \\"ISP2 enabled, acceptable packet loss on \\$interfa\\
    ce2\\"\\r\\
    \\n            /ip route set \\$i2 disabled=no\\r\\
    \\n            /ip firewall mangle enable [find comment=\\"via ISP2 only\\"]\\r\\
    \\n#            /ip firewall mangle enable [find comment=\\"PCC: new LAN to W\\
    AN connections for ISP2_conn\\"]\\r\\
    \\n        }\\r\\
    \\n    }\\r\\
    \\n}\\r\\
    \\n}"
add dont-require-permissions=yes name=CheckUpdate owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="# --- Fi\
    nal Stable RouterOS Update Script ---\
    \n\
    \n# 1. Trigger update check\
    \n/system package update set channel=stable\
    \n/system package update check-for-updates\
    \n\
    \n# 2. Wait for cloud response\
    \n:delay 20s\
    \n\
    \n# 3. Get update properties\
    \n:local update [/system package update get]\
    \n:local installed (\$update->\"installed-version\")\
    \n:local latest (\$update->\"latest-version\")\
    \n\
    \n# 4. Update logic\
    \n:if (\$installed != \$latest) do={\
    \n    :if ([:len \$latest] > 0) do={\
    \n        :log warning (\"OS_UPDATE: New version detected: \" . \$latest)\
    \n        \
    \n        # Start download process\
    \n        /system package update download\
    \n        :log warning \"OS_UPDATE: Download in progress...\"\
    \n        \
    \n        # 5. Wait loop (Max 5 minutes)\
    \n        :local count 0\
    \n        :local isDone false\
    \n        :while (\$count < 30 and \$isDone = false) do={\
    \n            :local currentStat [/system package update get status]\
    \n            # Check for 'downloaded' or 'reboot' in any case (case-insens\
    itive match)\
    \n            :if (\$currentStat ~ \"[Dd]ownload\" or \$currentStat ~ \"[Rr\
    ]eboot\") do={\
    \n                :set isDone true\
    \n            } else={\
    \n                :delay 10s\
    \n                :set count (\$count + 1)\
    \n            }\
    \n        }\
    \n\
    \n        # 6. Final verification before install\
    \n        :local finalStat [/system package update get status]\
    \n        # Match \"download\", \"reboot\", or \"install\" ignoring case\
    \n        :if (\$finalStat ~ \"[Dd]ownload\" or \$finalStat ~ \"[Rr]eboot\"\
    \_or \$finalStat ~ \"[Ii]nstall\") do={\
    \n            :log warning (\"OS_UPDATE: Ready! Status: \" . \$finalStat)\
    \n            :log warning \"OS_UPDATE: Executing install command...\"\
    \n            :delay 15s\
    \n            # This triggers the actual update process and reboot\
    \n            /system package update install\
    \n        } else={\
    \n            :log error (\"OS_UPDATE: Installation failed. Status: \" . \$\
    finalStat)\
    \n        }\
    \n    }\
    \n} else={\
    \n    :log info (\"OS_UPDATE: System is already up to date: \" . \$installe\
    d)\
    \n}\
    \n"
add dont-require-permissions=no name=FWApply owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="# --- Fi\
    rmware Auto-Apply Script (Triggered on Startup) ---\r\
    \n\r\
    \n# 1. Wait for system initialization and network stability\r\
    \n:delay 30s\r\
    \n\r\
    \n# 2. Compare current and upgrade firmware versions\r\
    \n:local rb [/system routerboard get]\r\
    \n:local current (\$rb->\"current-firmware\")\r\
    \n:local upgrade (\$rb->\"upgrade-firmware\")\r\
    \n\r\
    \n:if (\$current != \$upgrade) do={\r\
    \n    :log warning (\"System: Firmware mismatch detected! Current: \" . \$c\
    urrent . \" Upgrade: \" . \$upgrade)\r\
    \n    :log warning \"System: Upgrading RouterBOARD firmware and rebooting..\
    .\"\r\
    \n    \r\
    \n    # 3. Perform the upgrade\r\
    \n    /system routerboard upgrade\r\
    \n    \r\
    \n    # 4. Final reboot to apply changes\r\
    \n    /system reboot\r\
    \n} else={\r\
    \n    :log info \"System: RouterBOARD firmware is already up to date (\$cur\
    rent).\"\r\
    \n}"
add dont-require-permissions=no name=Autobackup owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="# --- Ba\
    ckup & 7-Day Cleanup Script (Filename Based) ---\r\
    \n\r\
    \n# --- Settings ---\r\
    \n:local host [/system identity get name]\r\
    \n:local curDate [/system clock get date]\r\
    \n:local keepDays 7\r\
    \n\r\
    \n# Parse current date (Assumes YYYY-MM-DD or Month/DD/YYYY format)\r\
    \n# This part converts current date to a total number of days for compariso\
    n\r\
    \n:local cY [:tonum [:pick \$curDate 0 4]]\r\
    \n:local cM [:tonum [:pick \$curDate 5 7]]\r\
    \n:local cD [:tonum [:pick \$curDate 8 10]]\r\
    \n:local curTotalDays ((\$cY * 372) + (\$cM * 31) + \$cD)\r\
    \n\r\
    \n:local cleanDate (\$cY . [:pick (\"0\" . \$cM) ([:len (\"0\" . \$cM)]-2) \
    [:len (\"0\" . \$cM)]] . [:pick (\"0\" . \$cD) ([:len (\"0\" . \$cD)]-2) [:\
    len (\"0\" . \$cD)]])\r\
    \n:local filename (\$host . \"-\" . \$cleanDate)\r\
    \n\r\
    \n# --- 1. Backup Action ---\r\
    \n/system backup save name=\$filename\r\
    \n/export file=\$filename\r\
    \n:log info (\"System: New backup and export created: \" . \$filename)\r\
    \n\r\
    \n:delay 15s\r\
    \n\r\
    \n# --- 2. Cleanup Action (Parsing Date from Filename) ---\r\
    \n:log info \"--- Starting 7-Day Filename-Based Cleanup ---\"\r\
    \n\r\
    \n:local hostLen [:len \$host]\r\
    \n:local files [/file find where (name~\".backup\" or name~\".rsc\")]\r\
    \n\r\
    \n:foreach f in=\$files do={\r\
    \n    :local fName [/file get \$f name]\r\
    \n    \r\
    \n    # Filter files belonging to this host\r\
    \n    :if (\$fName ~ \$host) do={\r\
    \n        \r\
    \n        # Extract date parts based on host name length\r\
    \n        # Index:   01234567890123456\r\
    \n        # Year starts at hostLen + 1\r\
    \n        :local fY [:tonum [:pick \$fName (\$hostLen + 1) (\$hostLen + 5)]\
    ]\r\
    \n        :local fM [:tonum [:pick \$fName (\$hostLen + 5) (\$hostLen + 7)]\
    ]\r\
    \n        :local fD [:tonum [:pick \$fName (\$hostLen + 7) (\$hostLen + 9)]\
    ]\r\
    \n        \r\
    \n        :if ([:len \$fY] > 0 and [:len \$fM] > 0 and [:len \$fD] > 0) do=\
    {\r\
    \n            :local fileTotalDays ((\$fY * 372) + (\$fM * 31) + \$fD)\r\
    \n            \r\
    \n            # Logic: If current days minus file days > keepDays, then del\
    ete\r\
    \n            :if ((\$curTotalDays - \$fileTotalDays) > \$keepDays) do={\r\
    \n                :log warning (\"System: Removing old backup (date-based):\
    \_\" . \$fName)\r\
    \n                /file remove \$fName\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n}\r\
    \n:log info \"--- Backup & Cleanup Finished ---\""
/zerotier
set zt1 identity="ZT_IDENTITY_PLACEHOLDER"
/zerotier interface
add allow-default=no allow-global=no allow-managed=yes disabled=no instance=\\
    zt1 name=LEGO network={{ZEROTIER_NETWORK_ID}}
/caps-man manager
set enabled=yes
/caps-man provisioning
add action=create-dynamic-enabled hw-supported-modes=a,ac \\
    master-configuration=local-cfg5 name-format=prefix-identity name-prefix=5G \\
    slave-configurations=wifi-cfg5
add action=create-dynamic-enabled master-configuration=local-cfg2 name-format=\\
    prefix-identity name-prefix=2G slave-configurations=wifi-cfg2
/ip smb
set enabled=no
/interface bridge port
add bridge={{LAN_BRIDGE}} ingress-filtering=no interface=ether3
add bridge={{LAN_BRIDGE}} ingress-filtering=no interface=ether4
add bridge={{LAN_BRIDGE}} ingress-filtering=no interface=ether5
add bridge={{LAN_BRIDGE}} ingress-filtering=no interface=ether6
add bridge={{LAN_BRIDGE}} ingress-filtering=no interface=ether7
add bridge={{LAN_BRIDGE}} ingress-filtering=no interface=ether8
add bridge={{GUEST_BRIDGE}} interface=vlan10-guest
/ip neighbor discovery-settings
set discover-interface-list=LAN lldp-mac-phy-config=yes
/ip settings
set allow-fast-path=no
/ipv6 settings
set disable-ipv6=yes forward=no
/interface bridge vlan
add bridge={{LAN_BRIDGE}} vlan-ids=1,10
/interface list member
add interface={{LAN_BRIDGE}} list=LAN
add interface={{GUEST_BRIDGE}} list=LAN
add interface={{WAN1}} list=WAN
add interface={{WAN2}} list=WAN
add interface=LEGO list=LAN
add interface=*1C list=OVPN
add interface=*AD list=OVPN
add interface=warcloud list=OVPN
/interface wifi capsman
set interfaces={{LAN_BRIDGE}} upgrade-policy=none
/interface wifi provisioning
add action=create-dynamic-enabled disabled=no master-configuration=cfg2-local \\
    name-format=%I-2G slave-configurations=cfg2-wifi slave-name-format=\\
    %I-2G-guest supported-bands=2ghz-ax
add action=create-dynamic-enabled disabled=no master-configuration=cfg5-local \\
    name-format=%I-5G slave-configurations=cfg5-wifi slave-name-format=\\
    %I-5G-guest supported-bands=5ghz-ax
/ip address
add address="{{WORK_GATEWAY}}/24" interface={{LAN_BRIDGE}} network={{WORK_NETWORK_BASE}}
add address="{{GUEST_GATEWAY}}/24" interface={{GUEST_BRIDGE}} network={{GUEST_NETWORK_BASE}}
/ip dhcp-client
add add-default-route=no comment=ISP1 default-route-tables=main interface=\\
    {{WAN1}} name={{WAN1}} script=":if (\\$bound = 1) do={\\r\\
    \\n    :log info (\\"ISP1 DHCP bound, gateway: \\" . \\$\\x22gateway-address\\x22)\\r\\
    \\n    /ip route set [find where comment=\\"ISP1 checker\\"] gateway=\\$\\x22gateway-address\\x22 disabled=no\\r\\
    \\n    /ip route set [find where comment=\\"ISP1\\"] disabled=no\\r\\
    \\n    /ip firewall mangle enable [find comment=\\"via ISP1 only\\"]\\r\\
    \\n#    /ip firewall mangle enable [find comment=\\"PCC: new LAN to WAN conne\\
    ctions for ISP1_conn\\"]\\r\\
    \\n} else={\\r\\
    \\n    :log warning \\"ISP1 DHCP unbound\\"\\r\\
    \\n    /ip route set [find where comment=\\"ISP1\\"] disabled=yes\\r\\
    \\n    /ip firewall mangle disable [find comment=\\"via ISP1 only\\"]\\r\\
    \\n#    /ip firewall mangle disable [find comment=\\"PCC: new LAN to WAN conn\\
    ections for ISP1_conn\\"]\\r\\
    \\n    :do {\\r\\
    \\n        /ip firewall connection remove [find connection-mark=\\"ISP1_conn\\
    \\"]\\r\\
    \\n    } on-error={\\r\\
    \\n        :log warning \\"Connection no more exist!\\"\\r\\
    \\n    }\\r\\
    \\n    /ip dns cache flush\\r\\
    \\n}" use-peer-dns=no
add add-default-route=no comment=ISP2 default-route-tables=main interface=\\
    {{WAN2}} name={{WAN2}} script=":if (\\$bound = 1) do={\\r\\
    \\n    :log info (\\"ISP2 DHCP bound, gateway: \\" . \\$\\x22gateway-address\\x22)\\r\\
    \\n    /ip route set [find where comment=\\"ISP2 checker\\"] gateway=\\$\\x22gateway-address\\x22 disabled=no\\r\\
    \\n    /ip route set [find where comment=\\"ISP2\\"] disabled=no\\r\\
    \\n    /ip firewall mangle enable [find comment=\\"via ISP2 only\\"]\\r\\
    \\n    /ip firewall mangle enable [find comment=\\"PCC: new LAN to WAN connec\\
    tions for ISP2_conn\\"]\\r\\
    \\n} else={\\r\\
    \\n    :log warning \\"ISP2 DHCP unbound\\"\\r\\
    \\n    /ip route set [find where comment=\\"ISP2\\"] disabled=yes\\r\\
    \\n    /ip firewall mangle disable [find comment=\\"via ISP2 only\\"]\\r\\
    \\n    /ip firewall mangle disable [find comment=\\"PCC: new LAN to WAN conne\\
    ctions for ISP2_conn\\"]\\r\\
    \\n    :do {\\r\\
    \\n        /ip firewall connection remove [find connection-mark=\\"ISP2_conn\\
    \\"]\\r\\
    \\n    } on-error={\\r\\
    \\n        :log warning \\"Connection no more exist!\\"\\r\\
    \\n    }\\r\\
    \\n    /ip dns cache flush\\r\\
    \\n}" use-peer-dns=no use-peer-ntp=no
/ip dhcp-server lease
add address=10.16.132.247 client-id=1:0:b:82:89:35:3f comment=\\
    "TKP Albatros 126-116" mac-address=00:0B:82:89:35:3F server=dhcp-work
add address=10.16.132.246 client-id=1:dc:2c:6e:91:f7:51 comment=Dnipro \\
    mac-address=DC:2C:6E:91:F7:51 server=dhcp-work
add address=10.16.132.244 client-id=1:d0:ea:11:49:c5:cf comment=TKP \\
    mac-address=D0:EA:11:49:C5:CF server=dhcp-work
add address=10.16.132.242 client-id=1:d0:ea:11:49:c3:dd comment=Room \\
    mac-address=D0:EA:11:49:C3:DD server=dhcp-work
add address=10.16.132.241 client-id=1:dc:2c:6e:ec:fa:30 comment="TKP Hall" \\
    mac-address=DC:2C:6E:EC:FA:30 server=dhcp-work
add address=10.16.132.238 client-id=1:d0:ea:11:49:c6:6 comment=Idalnya \\
    mac-address=D0:EA:11:49:C6:06 server=dhcp-work
add address=192.168.132.195 client-id=1:64:c6:d2:e6:7f:d7 comment=Printer \\
    mac-address=64:C6:D2:E6:7F:D7 server=dhcp-guest
add address=10.16.132.228 client-id=1:d4:35:38:a0:95:2c comment="Guest Router" \\
    mac-address=D4:35:38:A0:95:2C server=dhcp-work
add address=192.168.132.230 client-id=1:e0:bb:9e:40:3b:3a comment=Printer \\
    mac-address=E0:BB:9E:40:3B:3A server=dhcp-guest
add address=10.16.132.218 comment="Guest Router" mac-address=1C:56:8E:28:88:05 \\
    server=dhcp-work
add address=192.168.132.93 client-id=1:64:c6:d2:e4:fd:46 comment=Printer \\
    mac-address=64:C6:D2:E4:FD:46 server=dhcp-guest
add address=192.168.132.87 client-id=1:a4:d7:3c:14:72:6c comment=Printer \\
    mac-address=A4:D7:3C:14:72:6C server=dhcp-guest
add address=192.168.132.213 client-id=1:20:b:74:9b:e6:90 comment=\\
    "Printer (2 Floor)" mac-address=20:0B:74:9B:E6:90 server=dhcp-guest
add address=10.16.132.215 client-id=1:1c:56:8e:46:bf:45 comment="Guest Router" \\
    mac-address=1C:56:8E:46:BF:45 server=dhcp-work
add address=192.168.132.108 client-id=1:e0:bb:9e:b9:a5:8 comment=Printer \\
    mac-address=E0:BB:9E:B9:A5:08 server=dhcp-guest
add address=192.168.132.151 client-id=1:e0:bb:9e:40:3b:9d comment=Printer \\
    mac-address=E0:BB:9E:40:3B:9D server=dhcp-guest
add address=10.16.132.192 client-id=1:b4:b5:2f:76:51:54 comment=\\
    "Guest (2 Floor)" mac-address=B4:B5:2F:76:51:54 server=dhcp-work
add address=192.168.132.62 client-id=1:20:b:74:9b:e6:87 comment=\\
    "Printer (2 Floor)" mac-address=20:0B:74:9B:E6:87 server=dhcp-guest
add address=192.168.132.218 client-id=1:20:b:74:9b:e6:78 comment=\\
    "Printer (2 Floor)" mac-address=20:0B:74:9B:E6:78 server=dhcp-guest
add address=192.168.132.183 client-id=1:e0:bb:9e:3a:fd:fa comment=\\
    "Printer (2 Floor)" mac-address=E0:BB:9E:3A:FD:FA server=dhcp-guest
add address=192.168.132.61 client-id=1:e8:4d:ec:27:d6:81 comment=\\
    "Printer (2 Floor)" mac-address=E8:4D:EC:27:D6:81 server=dhcp-guest
add address=10.16.132.184 client-id=1:48:a9:8a:d2:f4:6e comment=\\
    "2 Floor Router #2" mac-address=48:A9:8A:D2:F4:6E server=dhcp-work
add address=10.16.132.185 client-id=1:dc:2c:6e:ed:b:91 comment=\\
    "2 Floor Router #1" mac-address=DC:2C:6E:ED:0B:91 server=dhcp-work
add address=10.16.132.186 client-id=1:d0:ea:11:49:cd:f2 comment=\\\
    "2 Floor Router #2.1" mac-address=D0:EA:11:49:CD:F2 server=dhcp-work
add address=10.16.132.183 client-id=1:d0:ea:11:49:c4:59 comment=\\
    "2 Floor Router #1.1" mac-address=D0:EA:11:49:C4:59 server=dhcp-work
add address=10.16.132.181 client-id=1:f4:1e:57:1d:8a:d7 comment=\\
    "2 Floor Router #3" mac-address=F4:1E:57:1D:8A:D7 server=dhcp-work
add address=10.16.132.182 client-id=1:d0:ea:11:49:c4:af comment=\\
    "2 Floor Router #3.1" mac-address=D0:EA:11:49:C4:AF server=dhcp-work
/ip dhcp-server network
add address={{WORK_NETWORK}} dhcp-option=tftp150,tftp66 dns-server=\\
    {{WORK_GATEWAY}},1.1.1.1,8.8.8.8 gateway={{WORK_GATEWAY}}
add address={{GUEST_NETWORK}} dns-server={{GUEST_GATEWAY}},1.1.1.1,8.8.8.8 gateway=\\
    {{GUEST_GATEWAY}}
/ip dns
set allow-remote-requests=yes servers={{DNS_SERVERS}}
/ip dns static
add address={{TFTP_SERVER}} name=v.p-root.org ttl=10s type=A
add address=10.16.250.4 name=rdps type=A
/ip firewall address-list
add address={{WORK_NETWORK}} list=local_work
add address={{GUEST_NETWORK}} list=local_guest
add address=0.0.0.0/8 comment="\\"This\\" Network" list=BOGONS
add address=224.0.0.0/4 comment=Multicast list=BOGONS
add address=240.0.0.0/4 comment="Reserved for Future Use" list=BOGONS
add address=255.255.255.255 comment="Limited Broadcast" list=BOGONS
add address=www.i.ua list=Blacklist-email
add address=www.meta.ua list=Blacklist-email
add address=www.online.ua list=Blacklist-email
add address=www.bigmir.net list=Blacklist-email
add address=www.zoho.com list=Blacklist-email
add address=www.yahoo.com list=Blacklist-email
add address=www.aol.com list=Blacklist-email
add address=www.mailfence.com list=Blacklist-email
add address=www.proton.me list=Blacklist-email
add address=mail.yandex.ru list=Blacklist-email
add address=mail.ru list=Blacklist-email
add address=10.16.132.228 comment="Guest Router (2 Floor)" list=INTERNET_ONLY
add address=10.16.132.218 comment="Guest Router (2 Floor)" list=INTERNET_ONLY
add address=10.16.132.215 comment="Guest Router (2 Floor)" list=INTERNET_ONLY
add address=10.16.132.192 comment="Guest (2 Floor)" list=INTERNET_ONLY
/ip firewall filter
add action=reject chain=forward dst-address-list=Blacklist-email reject-with=\\
    icmp-network-unreachable
add action=reject chain=forward dst-port=25,465,587 protocol=tcp reject-with=\\
    icmp-network-unreachable
add action=accept chain=forward comment=\\
    "defconf: accept established,related, untracked" connection-state=\\
    established,related,untracked
add action=drop chain=forward comment="Guest Isolation" out-interface-list=\\
    !WAN src-address-list=INTERNET_ONLY
add action=accept chain=input comment=CAPsMAN dst-port=5246-5247 in-interface=\\
    {{LAN_BRIDGE}} protocol=udp
add action=accept chain=input comment=\\
    "defconf: accept established,related,untracked" connection-state=\\
    established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=\\
    invalid
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment=\\
    "defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=drop chain=forward comment="Bridge Isolation" in-interface=\\
    {{GUEST_BRIDGE}} out-interface={{LAN_BRIDGE}}
add action=accept chain=input comment="Allow ZeroTier input" in-interface=LEGO
add action=accept chain=forward comment="Allow ZeroTier forward" in-interface=\\
    LEGO
add action=accept chain=forward comment="Allow ZeroTier forward out" \\
    out-interface=LEGO
add action=drop chain=input comment="defconf: drop all not coming from LAN" \\
    in-interface-list=!LAN
add action=accept chain=forward comment="defconf: accept in ipsec policy" \\
    ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" \\
    ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" \\
    connection-state=established,related disabled=yes
add action=accept chain=forward in-interface-list=LAN out-interface-list=WAN
add action=drop chain=forward comment="defconf: drop invalid" \\
    connection-state=invalid
add action=drop chain=forward comment=\\
    "defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat \\
    connection-state=new in-interface-list=WAN
/ip firewall mangle
add action=accept chain=prerouting comment="Bypass PCC for ZeroTier DST" \\
    disabled=yes dst-address=10.16.250.0/24 in-interface-list=LAN
add action=accept chain=prerouting comment="Bypass PCC for ZeroTier DST" \\
    disabled=yes dst-address={{WORK_NETWORK}} in-interface-list=LAN
add action=accept chain=prerouting comment="Bypass PCC for ZeroTier SRC" \\
    disabled=yes in-interface-list=LAN src-address=10.16.250.0/24
add action=mark-routing chain=prerouting comment="via ISP1 only" \\
    new-routing-mark=to_ISP1 src-address-list=VIA_ISP1
add action=mark-routing chain=prerouting comment="via ISP2 only" \\
    new-routing-mark=to_ISP2 src-address-list=VIA_ISP2
add action=accept chain=prerouting comment="Bypass PCC for ZeroTier SRC" \\
    disabled=yes in-interface-list=LAN src-address={{WORK_NETWORK}}
add action=accept chain=prerouting comment="bridge access" dst-address-list=\\
    local in-interface-list=LAN
add action=mark-connection chain=prerouting comment=\\
    "Mark established WAN connections for ISP1_conn" connection-mark=no-mark \\
    connection-state=established,related in-interface={{WAN1}} \\
    new-connection-mark=ISP1_conn
add action=mark-connection chain=prerouting comment=\\
    "Mark established WAN connections ISP2_conn" connection-mark=no-mark \\
    connection-state=established,related in-interface={{WAN2}} \\
    new-connection-mark=ISP2_conn
add action=mark-connection chain=prerouting comment=\\
    "PCC: new LAN to WAN connections for ISP1_conn" connection-mark=no-mark \\
    disabled=yes dst-address-type=!local in-interface-list=LAN \\
    new-connection-mark=ISP1_conn per-connection-classifier=\\
    both-addresses-and-ports:3/0
add action=mark-connection chain=prerouting comment=\\
    "PCC: new LAN to WAN connections for ISP2_conn" connection-mark=no-mark \\
    dst-address-type=!local in-interface-list=LAN new-connection-mark=\\
    ISP2_conn per-connection-classifier=both-addresses-and-ports:3/1
add action=mark-routing chain=prerouting comment="Mark routing for ISP1_conn" \\
    connection-mark=ISP1_conn in-interface-list=LAN new-routing-mark=to_ISP1
add action=mark-routing chain=prerouting comment="Mark routing for ISP2_conn" \\
    connection-mark=ISP2_conn in-interface-list=LAN new-routing-mark=to_ISP2
add action=mark-routing chain=output comment="Mark routing for ISP1_conn" \\
    connection-mark=ISP1_conn dst-address-type=!local new-routing-mark=to_ISP1
add action=mark-routing chain=output comment="Mark routing for ISP2_conn" \\
    connection-mark=ISP2_conn dst-address-type=!local new-routing-mark=to_ISP2
/ip firewall nat
add action=masquerade chain=srcnat comment=defconf ipsec-policy=out,none \\
    out-interface-list=WAN
add action=masquerade chain=srcnat comment=masquerade ipsec-policy=out,none \\
    out-interface-list=OVPN
/ip route
add check-gateway=ping comment="ISP1 checker" disabled=no distance=1 \\
    dst-address=1.1.1.1/32 gateway=192.168.226.1 routing-table=main scope=10 \\
    target-scope=10
add check-gateway=ping comment="ISP2 checker" disabled=no distance=1 \\
    dst-address=1.0.0.1/32 gateway=192.168.1.1 routing-table=main scope=10 \\
    target-scope=10
add check-gateway=ping comment=ISP1 disabled=no distance=1 dst-address=\\
    0.0.0.0/0 gateway=1.1.1.1 routing-table=main scope=10 target-scope=11
add check-gateway=ping comment=ISP2 disabled=no distance=3 dst-address=\\
    0.0.0.0/0 gateway=1.0.0.1 routing-table=main scope=10 target-scope=11
add comment="ISP1 checker" disabled=no distance=1 dst-address=8.8.8.8/32 \\
    gateway=192.168.226.1 routing-table=main scope=10 target-scope=10
add comment="ISP2 checker" disabled=no distance=1 dst-address=8.8.4.4/32 \\
    gateway=192.168.1.1 routing-table=main scope=10 target-scope=10
add check-gateway=ping comment=ISP1 disabled=no distance=1 dst-address=\\
    0.0.0.0/0 gateway=1.1.1.1 routing-table=to_ISP1 scope=10 target-scope=11
add check-gateway=ping comment=ISP1 disabled=no distance=2 dst-address=\\
    0.0.0.0/0 gateway=8.8.8.8 routing-table=to_ISP1 scope=10 target-scope=11
add check-gateway=ping comment=ISP2 disabled=no distance=3 dst-address=\\
    0.0.0.0/0 gateway=1.0.0.1 routing-table=to_ISP2 scope=10 target-scope=11
add check-gateway=ping comment=ISP2 disabled=no distance=4 dst-address=\\
    0.0.0.0/0 gateway=8.8.4.4 routing-table=to_ISP2 scope=10 target-scope=11
add dst-address=10.0.1.120 gateway=""
add dst-address=10.194.0.0/24 gateway=""
add dst-address=10.0.1.120 gateway=""
add dst-address=10.194.0.0/24 gateway=""
add dst-address=10.0.1.120 gateway=warcloud
add dst-address=10.194.0.0/24 gateway=warcloud
/ip service
set ftp disabled=yes
set telnet disabled=yes
set www disabled=yes
set reverse-proxy disabled=yes
set api disabled=yes
set api-ssl disabled=yes
set ssh port=20522
/ip traffic-flow
set active-flow-timeout=1m cache-entries=16k enabled=yes \\
    inactive-flow-timeout=5s
/ip traffic-flow target
add dst-address=10.0.1.120 src-address=10.193.132.66
add dst-address=10.0.1.120 src-address=10.193.128.244
add dst-address=10.0.1.120 src-address=10.193.128.244
add dst-address=10.0.1.120 src-address=10.193.134.204
/snmp
set enabled=yes trap-generators="" trap-version=2
/system clock
set time-zone-autodetect=no time-zone-name=Europe/Kiev
/system identity
set name={{SITE_NAME}}
/system logging
add action=remote topics=info
add action=remote topics=system
add action=remote topics=dns
add action=remote topics=warning
add action=remote topics=critical
add action=remote topics=error
add action=graylog topics=info
add action=graylog topics=error
add action=graylog topics=warning
add action=remote topics=info
add action=remote topics=system
add action=remote topics=dns
add action=remote topics=warning
add action=remote topics=critical
add action=remote topics=error
add action=remote topics=info
add action=remote topics=system
add action=remote topics=dns
add action=remote topics=warning
add action=remote topics=critical
add action=remote topics=error
add action=remote topics=info
add action=remote topics=system
add action=remote topics=dns
add action=remote topics=warning
add action=remote topics=critical
add action=remote topics=error
/system note
set show-at-login=no
/system ntp client
set enabled=yes
/system ntp server
set enabled=yes
/system ntp client servers
add address=ua.pool.ntp.org
add address=us.pool.ntp.org
/system scheduler
add disabled=yes interval=1m name=run_keep_conn_quality on-event=\\
    keep_conn_quality policy=read,write,policy,test start-date=2025-08-14 \\
    start-time=12:12:21
add interval=1w name=run_CheckUpdate on-event=CheckUpdate policy=\\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\\
    2026-03-01 start-time=03:30:00
add name=Check_FWApply on-event=FWApply policy=\\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-time=\\
    startup
add interval=2w name=run_Autobackup on-event=Autobackup policy=\\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=\\
    2026-03-01 start-time=03:00:00
"""
    }
}
