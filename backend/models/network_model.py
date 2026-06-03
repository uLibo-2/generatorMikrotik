from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class InterfaceModel(BaseModel):
    name: str
    type: str # ethernet, vlan, wifi, bridge, etc.
    disabled: bool = False
    pvid: Optional[int] = None
    vlan_ids: Optional[List[int]] = None
    comment: Optional[str] = None

class BridgeVlanModel(BaseModel):
    bridge: str
    vlan_ids: List[int]
    tagged: List[str] = []
    untagged: List[str] = []

class BridgePortModel(BaseModel):
    interface: str
    bridge: str
    pvid: int = 1
    hw: bool = True
    frame_types: Optional[str] = None
    ingress_filtering: bool = False
    edge: Optional[str] = None # auto, yes, no

class BridgeModel(BaseModel):
    name: str
    vlan_filtering: bool = False
    ports: List[BridgePortModel] = []
    vlans: List[BridgeVlanModel] = []

class VlanInterfaceModel(BaseModel):
    name: str
    vlan_id: int
    interface: str

class IPAddressModel(BaseModel):
    address: str
    interface: str
    network: Optional[str] = None

class DHCPPoolModel(BaseModel):
    name: str
    ranges: List[str]

class DHCPStaticLease(BaseModel):
    mac_address: str
    address: str
    comment: Optional[str] = None

class DHCPServerModel(BaseModel):
    name: str
    interface: str
    address_pool: str
    disabled: bool = False
    lease_time: Optional[str] = None

class DHCPNetworkModel(BaseModel):
    address: str
    gateway: str
    dns_server: Optional[str] = None

class WifiInterfaceModel(BaseModel):
    name: str
    ssid: str
    security_profile: Optional[str] = None
    master_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    disabled: bool = False

class FirewallRuleModel(BaseModel):
    chain: str
    action: str
    src_address: Optional[str] = None
    dst_address: Optional[str] = None
    src_address_list: Optional[str] = None
    dst_address_list: Optional[str] = None
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None
    in_interface_list: Optional[str] = None
    out_interface_list: Optional[str] = None
    protocol: Optional[str] = None
    dst_port: Optional[str] = None
    connection_state: Optional[str] = None
    comment: Optional[str] = None
    disabled: bool = False
    line: str = ""

class RouterOSService(BaseModel):
    name: str
    port: int
    disabled: bool = False
    address: Optional[str] = None

class NetworkModel(BaseModel):
    version: str = "7.20"
    major_version: int = 7
    hardware: str = "Unknown"
    interfaces: List[InterfaceModel] = []
    bridges: List[BridgeModel] = []
    vlans: List[VlanInterfaceModel] = []
    ips: List[IPAddressModel] = []
    dhcp_pools: List[DHCPPoolModel] = []
    dhcp_servers: List[DHCPServerModel] = []
    dhcp_networks: List[DHCPNetworkModel] = []
    dhcp_static_leases: List[DHCPStaticLease] = []
    wifi: List[WifiInterfaceModel] = []
    firewall_rules: List[FirewallRuleModel] = []
    firewall_nat: List[FirewallRuleModel] = []
    firewall_mangle: List[FirewallRuleModel] = []
    services: List[RouterOSService] = []
    dns_servers: List[str] = []
    dns_allow_remote: bool = False
    ntp_enabled: bool = False
    ntp_servers: List[str] = []
    snmp_enabled: bool = False
    snmp_community: Optional[str] = None
    syslog_enabled: bool = False
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    backup_script_exists: bool = False
    rsc_export_script_exists: bool = False
    raw_sections: Dict[str, List[str]] = {}

class ConfigGenRequest(BaseModel):
    device_type: str = "hap-ax3"
    ros_version: str = "7.20"
    vlans: List[Dict[str, Any]] = []
    ssids: List[Dict[str, Any]] = []
    country: str = "Ukraine"
    capsman: bool = False
    wifi_password: Optional[str] = "SecureWiFi123!"
    dns_mode: Optional[str] = "cloudflare"
    dns_custom: Optional[str] = ""
    ntp_mode: Optional[str] = "pool"
    ntp_custom: Optional[str] = ""
    firewall_profile: Optional[str] = "basic"
