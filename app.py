import re
import sqlite3
import json
import webbrowser
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Import modular platform modules
from backend.models.network_model import ConfigGenRequest
from backend.parsers.network_model import parse_to_model
from backend.audit.engine import full_audit
from backend.audit.compliance import audit_compliance, apply_policy_to_config
from backend.repair.generator import generate_config, auto_repair_config
from backend.repair.diff import generate_config_diff

# Import design suite modules
from backend.design.templates import TEMPLATES
from backend.design.designer import (
    PROFILES,
    verify_ip_plan,
    generate_connectivity_scheme,
    generate_vlan_table_data,
    generate_markdown_documentation
)
from backend.design.cloner import clone_site_config

# Import template extraction engine modules
from backend.design.extractor import (
    extract_template,
    clone_site_blueprint,
    bulk_clone,
    compare_configs
)

app = FastAPI(title="MikroTik Platform v2.5 Suite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "knowledge.db"
STATIC_DIR = BASE_DIR / "static"

# ─── DB Init ─────────────────────────────────────────────────────────────────

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            problem TEXT NOT NULL,
            solution TEXT NOT NULL,
            tags TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            used_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            summary TEXT,
            issues_count INTEGER,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ─── Pydantic Request Models ──────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    config: str
    filename: Optional[str] = "config.rsc"

class RebuildRequest(BaseModel):
    config: str
    profile: Optional[str] = "basic" # basic, secure, hardened, enterprise, isp

class TroubleshootRequest(BaseModel):
    problem: str

class KnowledgeEntry(BaseModel):
    problem: str
    solution: str
    tags: Optional[str] = ""

class CompareRequest(BaseModel):
    config_old: str
    config_new: str

class PolicyConfig(BaseModel):
    disabled_services: Optional[List[str]] = ["telnet", "ftp", "www", "api", "api-ssl"]
    enabled_services: Optional[List[str]] = ["winbox", "ssh"]
    winbox_port: Optional[int] = 8291
    ssh_port: Optional[int] = 22
    winbox_allowed_addresses: Optional[str] = ""
    ssh_allowed_addresses: Optional[str] = ""
    disable_ipv6: Optional[bool] = True
    identity_prefix: Optional[str] = ""
    identity_regex: Optional[str] = ""
    identity_example: Optional[str] = ""
    syslog_enabled: Optional[bool] = False
    syslog_host: Optional[str] = ""
    syslog_port: Optional[int] = 514
    syslog_topics: Optional[str] = "!debug,!packet"
    ssh_strong_crypto: Optional[bool] = True
    ntp_primary: Optional[str] = ""
    ntp_secondary: Optional[str] = ""
    dns_servers: Optional[str] = ""
    custom_rules: Optional[List[Dict[str, Any]]] = []

POLICY_PATH = BASE_DIR / "data" / "policy.json"

# Helper for policy operations
def load_policy() -> dict:
    if POLICY_PATH.exists():
        try:
            return json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        except:
            return {}
    return {}

def save_policy(policy: dict):
    POLICY_PATH.parent.mkdir(exist_ok=True)
    POLICY_PATH.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    result = full_audit(req.config)

    # Append compliance data if policy exists
    policy = load_policy()
    if policy:
        from backend.parsers.network_model import parse_to_model as _parse
        model = _parse(req.config)
        result["compliance"] = audit_compliance(model, policy)

    # Save to history
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO audit_history (filename, summary, issues_count) VALUES (?,?,?)",
        (req.filename, json.dumps(result["summary"]), result["summary"]["total_issues"])
    )
    conn.commit()
    conn.close()
    return result

@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    content = await file.read()
    try:
        config_text = content.decode("utf-8")
    except UnicodeDecodeError:
        config_text = content.decode("latin-1")

    result = full_audit(config_text)

    # Append compliance data if policy exists
    policy = load_policy()
    if policy:
        from backend.parsers.network_model import parse_to_model as _parse
        model = _parse(config_text)
        result["compliance"] = audit_compliance(model, policy)

    # Save to history
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO audit_history (filename, summary, issues_count) VALUES (?,?,?)",
        (file.filename, json.dumps(result["summary"]), result["summary"]["total_issues"])
    )
    conn.commit()
    conn.close()
    return result

@app.post("/api/analyze/rebuild")
async def rebuild_configuration_api(req: RebuildRequest):
    result = auto_repair_config(req.config, req.profile)
    return result

@app.post("/api/generate")
async def generate_api(req: ConfigGenRequest):
    # Retrieve default policy to append if any exists
    lines = generate_config(req).splitlines()
    policy = load_policy()
    if policy:
        lines = apply_policy_to_config(lines, policy)
    return {"config": "\n".join(lines)}

@app.post("/api/compare")
async def compare_configs_api(req: CompareRequest):
    diff_text = generate_config_diff(req.config_old, req.config_new)
    return {"diff": diff_text}

class DesignGenerateRequest(BaseModel):
    template_id: str
    variables: Dict[str, str]

class CloneRequest(BaseModel):
    config: str
    src_base: str
    dst_base: str

@app.get("/api/design/templates")
async def get_design_templates():
    return {
        "templates": TEMPLATES,
        "profiles": PROFILES
    }

@app.post("/api/design/generate")
async def generate_designed_config(req: DesignGenerateRequest):
    template_id = req.template_id
    variables = req.variables

    if template_id not in TEMPLATES:
        return JSONResponse(status_code=400, content={"error": f"Шаблон '{template_id}' не знайдено"})

    template = TEMPLATES[template_id]
    config_text = template["config"]

    # Perform variable replacements
    for k, v in variables.items():
        config_text = config_text.replace(f"{{{{{k}}}}}", str(v))

    # Build vlan list from variables for IP plan validation
    vlan_list = []
    vlans_to_add = [
        ("MGMT_VLAN", "MGMT_SUBNET", "MGMT_GATEWAY", "mgmt"),
        ("STAFF_VLAN", "STAFF_SUBNET", "STAFF_GATEWAY", "staff"),
        ("GUEST_VLAN", "GUEST_SUBNET", "GUEST_GATEWAY", "guest"),
        ("IOT_VLAN", "IOT_SUBNET", "IOT_GATEWAY", "iot"),
        ("CCTV_VLAN", "CCTV_SUBNET", "CCTV_GATEWAY", "cctv")
    ]

    for v_id_key, subnet_key, gw_key, fallback_name in vlans_to_add:
        v_id = variables.get(v_id_key)
        subnet = variables.get(subnet_key)
        gateway = variables.get(gw_key)
        if v_id or subnet or gateway:
            vlan_list.append({
                "id": v_id if v_id else "",
                "name": fallback_name,
                "subnet": subnet if subnet else "",
                "gateway": gateway if gateway else ""
            })

    ip_plan_errors = verify_ip_plan(vlan_list)

    vlan_table = generate_vlan_table_data(variables)
    documentation = generate_markdown_documentation(template_id, variables, vlan_table)
    connectivity_scheme = generate_connectivity_scheme(template_id, variables)

    # Apply policy if exists to the generated config
    policy = load_policy()
    if policy:
        lines = config_text.splitlines()
        lines = apply_policy_to_config(lines, policy)
        config_text = "\n".join(lines)

    # Pre-generation audit using the existing engine
    audit_report = full_audit(config_text)

    return {
        "config": config_text,
        "documentation": documentation,
        "connectivity_scheme": connectivity_scheme,
        "vlan_table": vlan_table,
        "ip_plan_errors": ip_plan_errors,
        "audit": audit_report
    }

@app.post("/api/design/clone")
async def clone_site_api(req: CloneRequest):
    try:
        cloned = clone_site_config(req.config, req.src_base, req.dst_base)
        return {"cloned_config": cloned}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

class ExtractRequest(BaseModel):
    config: str

class CloneBlueprintRequest(BaseModel):
    config: str
    overrides: Dict[str, str]

class BulkCloneRequest(BaseModel):
    config: str
    sites: List[Dict[str, Any]]

class CompareSitesRequest(BaseModel):
    config_a: str
    config_b: str

@app.post("/api/design/extract")
async def extract_template_api(req: ExtractRequest):
    try:
        res = extract_template(req.config)
        return res
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/design/clone-blueprint")
async def clone_site_blueprint_api(req: CloneBlueprintRequest):
    try:
        cloned = clone_site_blueprint(req.config, req.overrides)
        return {"cloned_config": cloned}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/design/bulk-clone")
async def bulk_clone_api(req: BulkCloneRequest):
    try:
        results = bulk_clone(req.config, req.sites)
        return {"results": results}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/design/compare-sites")
async def compare_sites_api(req: CompareSitesRequest):
    try:
        res = compare_configs(req.config_a, req.config_b)
        return res
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

class CompileRequest(BaseModel):
    config: str
    target_hardware: str = "hAP_ax3"
    src_subnet: Optional[str] = None
    target_subnet: Optional[str] = None
    target_ssid: Optional[str] = None
    target_wifi_password: Optional[str] = None

@app.post("/api/design/compile")
async def compile_config_api(req: CompileRequest):
    try:
        from backend.parsers.ast_parser import RouterOS_AST
        from backend.design.migration import (
            ReferenceResolver,
            MigrationRiskAnalyzer,
            ValidationSandbox,
            DigitalTwin,
            ComplianceEngine,
            SecretExtractor,
            RollbackGenerator,
            DisasterRecoveryPack,
            HeuristicsOptimizer,
            deepcopy_ast
        )
        import ipaddress

        if not req.config.strip():
            return JSONResponse(status_code=400, content={"error": "Вхідна конфігурація порожня."})

        ast = RouterOS_AST.parse_rsc(req.config)

        # Apply overrides to ast before sandbox validations
        from backend.design.migration import IPRecalculator
        src_subnet = req.src_subnet
        if req.target_subnet:
            if not src_subnet:
                for node in ast.nodes:
                    if node.path == "/ip address" and node.action == "add":
                        addr = node.params.get("address", "").strip('"\'')
                        if addr and "/" in addr:
                            try:
                                src_subnet = str(ipaddress.ip_network(addr, strict=False))
                                break
                            except:
                                pass
                if not src_subnet:
                    src_subnet = "192.168.88.0/24"
            ast = IPRecalculator.recalculate_ast_ips(ast, src_subnet, req.target_subnet)

        if req.target_ssid:
            for node in ast.nodes:
                if node.path in ["/interface wifi configuration", "/interface wireless", "/caps-man configuration"]:
                    if "ssid" in node.params:
                        node.params["ssid"] = f'"{req.target_ssid}"'

        if req.target_wifi_password:
            for node in ast.nodes:
                if node.path == "/interface wireless security-profiles" and node.action == "add":
                    if "wpa2-pre-shared-key" in node.params:
                        node.params["wpa2-pre-shared-key"] = f'"{req.target_wifi_password}"'
                    if "passphrase" in node.params:
                        node.params["passphrase"] = f'"{req.target_wifi_password}"'
                elif node.path in ["/interface wifi security", "/caps-man security"] and node.action == "add":
                    if "passphrase" in node.params:
                        node.params["passphrase"] = f'"{req.target_wifi_password}"'

        resolved = ReferenceResolver.resolve_ast_references(deepcopy_ast(ast))

        # Check source model from comments
        src_model = "RB5009"
        for node in ast.nodes:
            if node.comment:
                match = re.search(r'model\s*=\s*([^\s#\n\r]+)', node.comment)
                if match:
                    src_model = match.group(1).strip()
                    if "5009" in src_model:
                        src_model = "RB5009"
                    elif "ax3" in src_model:
                        src_model = "hAP_ax3"
                    elif "ac2" in src_model:
                        src_model = "hAP_ac2"
                    elif "ac3" in src_model:
                        src_model = "hAP_ac2"
                    elif "lite" in src_model:
                        src_model = "hAP_lite"

        risks = MigrationRiskAnalyzer.analyze_risks(src_model, req.target_hardware)
        sandbox_errors = ValidationSandbox.validate_config(ast)

        pack = DisasterRecoveryPack.assemble_dr_pack(
            req.config,
            req.target_hardware,
            src_subnet=src_subnet,
            target_subnet=req.target_subnet,
            target_ssid=req.target_ssid,
            target_wifi_password=req.target_wifi_password
        )

        compiled_ast = RouterOS_AST.parse_rsc(pack["new_config"])
        compliance = ComplianceEngine.audit_security(compiled_ast)

        # Flow Analyzers & WiFi Audit
        from backend.design.migration import (
            FirewallFlowAnalyzer,
            NATFlowAnalyzer,
            RoutingFlowAnalyzer,
            WiFiAuditor,
            MermaidGenerator,
            ChangeImpactEngine,
            AutoRepairEngine,
            CapacityPlanner,
            InterfaceIntentEngine
        )

        fw_flow = FirewallFlowAnalyzer.analyze_flow(compiled_ast)
        nat_flow = NATFlowAnalyzer.analyze_nat(compiled_ast)
        routing_flow = RoutingFlowAnalyzer.analyze_routing(compiled_ast)
        wifi_audit = WiFiAuditor.analyze_wifi(compiled_ast)

        # Append routing / PCC failures to sandbox errors to trigger confidence deductions
        for warning in routing_flow["warnings"]:
            sandbox_errors.append(warning)

        opt_report = HeuristicsOptimizer.optimize_and_score(compiled_ast, risks, sandbox_errors, compliance)

        # Mermaid Topology
        compiled_resolved = ReferenceResolver.resolve_ast_references(compiled_ast)
        compiled_intents = InterfaceIntentEngine.classify_interfaces(compiled_ast)
        mermaid_code = MermaidGenerator.generate(compiled_resolved, compiled_intents)
        pack["mermaid_topology"] = mermaid_code

        # Change Impact
        orig_ast = RouterOS_AST.parse_rsc(req.config)
        change_impacts = ChangeImpactEngine.analyze_impact(orig_ast, compiled_ast)

        # Auto-Repair Fixes
        auto_fixes = AutoRepairEngine.suggest_fixes(compiled_ast, sandbox_errors)

        # Capacity Plan
        capacity_report = CapacityPlanner.estimate_capacity(compiled_ast, req.target_hardware)

        pack["inventory"]["quality_score"] = opt_report["quality_score"]
        pack["inventory"]["confidence_score"] = opt_report["confidence_score"]
        pack["inventory"]["confidence_deductions"] = opt_report.get("confidence_deductions", [])
        pack["inventory"]["recommendations"] = opt_report["recommendations"]
        pack["inventory"]["ai_review"] = opt_report.get("ai_review", [])
        pack["inventory"]["readiness_breakdown"] = opt_report["readiness_breakdown"]
        pack["inventory"]["risks"] = risks
        pack["inventory"]["sandbox_errors"] = sandbox_errors
        pack["inventory"]["firewall_flow"] = fw_flow
        pack["inventory"]["nat_flow"] = nat_flow
        pack["inventory"]["routing_flow"] = routing_flow
        pack["inventory"]["wifi_audit"] = wifi_audit
        pack["inventory"]["change_impacts"] = change_impacts
        pack["inventory"]["auto_fixes"] = auto_fixes
        pack["inventory"]["capacity_report"] = capacity_report

        return pack
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=400, content={"error": str(e)})

class ExpertDesignRequest(BaseModel):
    clients_count: int = 50
    wan_count: int = 1
    wifi_needed: bool = True
    capsman_needed: bool = False
    vpn_needed: bool = False
    container_needed: bool = False

@app.post("/api/design/expert")
async def expert_design_api(req: ExpertDesignRequest):
    if req.clients_count >= 200 or req.container_needed:
        core_model = "RB5009"
        core_desc = "Рекомендовано високопродуктивний RB5009UG+S+IN для високого навантаження та Docker контейнерів."
    elif req.clients_count >= 50 or req.wan_count > 1 or req.capsman_needed:
        core_model = "hAP_ax3"
        core_desc = "Рекомендовано hAP ax3 як основний маршрутизатор із потужним 4-ядерним процесором та підтримкою Wi-Fi 6."
    else:
        core_model = "hAP_ac2"
        core_desc = "Рекомендовано компактний та бюджетний hAP ac2 для домашніх мереж чи малих офісів."

    if req.wifi_needed:
        if req.capsman_needed or req.clients_count >= 50:
            ap_model = "cAP_ax"
            ap_count = max(1, int(req.clients_count / 30))
            ap_desc = f"Рекомендовано стельові точки cAP ax у кількості {ap_count} шт. під керуванням CAPsMAN контролера."
        else:
            ap_model = core_model + " (Вбудований Wi-Fi)"
            ap_count = 1
            ap_desc = "Для бездротової мережі достатньо інтегрованого Wi-Fi інтерфейсу на основному маршрутизаторі."
    else:
        ap_model = "Без Wi-Fi"
        ap_count = 0
        ap_desc = "Бездротові точки доступу не потрібні згідно з вимогами."

    vlans = [
        {"id": 99, "name": "MGMT_VLAN", "subnet": "192.168.99.0/24", "desc": "Керування пристроями (Management)"}
    ]
    if req.clients_count > 10:
        vlans.append({"id": 10, "name": "OFFICE_VLAN", "subnet": "10.10.10.0/24", "desc": "Основна робоча мережа (Staff)"})
    if req.wifi_needed:
        vlans.append({"id": 20, "name": "GUEST_VLAN", "subnet": "10.20.20.0/24", "desc": "Гостьовий сегмент Wi-Fi"})
    if req.clients_count > 20:
        vlans.append({"id": 30, "name": "IOT_VLAN", "subnet": "10.30.30.0/24", "desc": "Мережа розумного дому чи IoT"})

    return {
        "core_device": core_model,
        "core_desc": core_desc,
        "access_ap": ap_model,
        "ap_count": ap_count,
        "ap_desc": ap_desc,
        "vlans": vlans,
        "architecture_summary": f"Мережевий дизайн для {req.clients_count} клієнтів з {req.wan_count} WAN лінком."
    }

class SimulateRequest(BaseModel):
    model_key: str
    clients_count: int = 50
    wan_speed_mbps: int = 1000
    config: Optional[str] = ""

class AdvisorRequest(BaseModel):
    clients_count: int = 50
    wan_count: int = 1
    wifi_needed: bool = True
    vpn_needed: bool = False
    vlan_needed: bool = True
    internet_speed: int = 1000

class GeneratorRequest(BaseModel):
    office_name: str = "Enterprise"
    clients_count: int = 50
    wan_count: int = 1
    ap_count: int = 1
    guest_wifi: bool = True
    voip_needed: bool = False
    cctv_needed: bool = False
    management_needed: bool = True
    workstations_needed: bool = True

class PacketTraceRequest(BaseModel):
    config: str
    src_ip: str
    dst_ip: str
    protocol: str = "tcp"
    dst_port: str = "80"
    connection_state: str = "new"

@app.get("/api/wiki/learn")
async def wiki_learn(q: str):
    from backend.knowledgebase.learning import LearningEngine
    return LearningEngine.explain_concept(q)

@app.get("/api/wiki/explain")
async def wiki_explain(q: str):
    from backend.knowledgebase.learning import LearningEngine
    return LearningEngine.explain_concept(q)

@app.get("/api/design/query-impact")
async def query_impact(q: str, config: Optional[str] = ""):
    from backend.parsers.ast_parser import RouterOS_AST
    from backend.dependency.graph import RouterOSSemanticGraph

    if not config or not config.strip():
        config = "/interface bridge add name=bridge"

    ast = RouterOS_AST.parse_rsc(config)
    graph = RouterOSSemanticGraph.build_from_ast(ast)
    affected = graph.get_affected_nodes(q)
    return {"affected": affected}

@app.post("/api/design/simulate")
async def simulate_capacity_api(req: SimulateRequest):
    from backend.parsers.ast_parser import RouterOS_AST
    from backend.design.migration import CapacityPlanner
    config_text = req.config or "/interface bridge add name=bridge"
    ast = RouterOS_AST.parse_rsc(config_text)
    res = CapacityPlanner.estimate_capacity(ast, req.model_key, clients_count=req.clients_count, wan_speed_mbps=req.wan_speed_mbps)
    return res

@app.post("/api/design/advisor")
async def advisor_api(req: AdvisorRequest):
    if req.clients_count >= 1000 or req.internet_speed >= 5000:
        core_model = "CCR2004"
        core_name = "CCR2004-16G-2S+"
        core_desc = "Рекомендовано промисловий маршрутизатор CCR2004-16G-2S+ для великого навантаження, BGP Full Table та гігабітного трафіку."
        est_load = 25
    elif req.clients_count >= 200 or req.internet_speed >= 2000:
        core_model = "RB5009"
        core_name = "RB5009UG+S+IN"
        core_desc = "Рекомендовано високопродуктивний RB5009UG+S+IN для середніх та великих офісів із підтримкою Docker контейнерів."
        est_load = 40
    elif req.clients_count >= 50 or req.wan_count > 1 or req.vpn_needed:
        core_model = "hAP_ax3"
        core_name = "hAP ax3"
        core_desc = "Рекомендовано hAP ax3 як оптимальний вибір для офісів до 80 клієнтів. Має потужний 4-ядерним процесор."
        est_load = 45
    else:
        core_model = "hAP_ax2"
        core_name = "hAP ax2"
        core_desc = "Рекомендовано hAP ax2 для домашніх мереж або невеликих віддалених офісів."
        est_load = 30

    if req.wifi_needed:
        ap_model = "cAP_ax"
        ap_name = "cAP ax"
        ap_count = max(1, int(req.clients_count / 30))
        ap_desc = f"Рекомендовано стельові точки cAP ax у кількості {ap_count} шт. під керуванням CAPsMAN контролера."
    else:
        ap_model = "None"
        ap_name = "Без Wi-Fi"
        ap_count = 0
        ap_desc = "Бездротові точки доступу не потрібні відповідно до вимог."

    if req.clients_count > 20:
        sw_model = "CRS326"
        sw_name = "CRS326-24G-2S+RM"
        sw_count = max(1, int(req.clients_count / 24))
        sw_desc = f"Рекомендовано комутатори доступу CRS326 у кількості {sw_count} шт. для L2 VLAN комутації."
    else:
        sw_model = "None"
        sw_name = "Без додаткових комутаторів"
        sw_count = 0
        sw_desc = "Портів основного маршрутизатора достатньо для підключення клієнтів."

    vlans = [
        {"id": 99, "name": "MGMT_VLAN", "subnet": "192.168.99.0/24", "desc": "Керування пристроями"},
        {"id": 10, "name": "OFFICE_VLAN", "subnet": "10.10.10.0/24", "desc": "Основна робоча мережа (Staff)"}
    ]
    if req.wifi_needed:
        vlans.append({"id": 20, "name": "GUEST_VLAN", "subnet": "10.20.20.0/24", "desc": "Гостьова Wi-Fi мережа"})
    if req.clients_count > 30:
        vlans.append({"id": 30, "name": "VOIP_VLAN", "subnet": "10.30.30.0/24", "desc": "IP-телефонія (VoIP)"})
        vlans.append({"id": 40, "name": "CCTV_VLAN", "subnet": "10.40.40.0/24", "desc": "Системи відеоспостереження"})

    return {
        "core_device": core_name,
        "core_model": core_model,
        "core_desc": core_desc,
        "access_ap": ap_name,
        "ap_count": ap_count,
        "ap_desc": ap_desc,
        "switch_device": sw_name,
        "switch_count": sw_count,
        "switch_desc": sw_desc,
        "estimated_load_percent": est_load,
        "vlans": vlans
    }

@app.post("/api/design/generator")
async def generator_api(req: GeneratorRequest):
    config_lines = []
    config_lines.append(f"# model = hAP_ax3\n# version = 7.20\n# project = {req.office_name}")
    config_lines.append("/system identity")
    config_lines.append(f"set name=\"Router-{req.office_name}\"")

    config_lines.append("\n/interface bridge")
    config_lines.append("add name=bridge vlan-filtering=yes protocol-mode=rstp comment=\"Main Local Switch\"")

    vlans_to_create = []
    vlans_to_create.append((99, "MGMT_VLAN", "192.168.99.1/24", "192.168.99.10-192.168.99.200", "192.168.99.0/24"))
    if req.workstations_needed:
        vlans_to_create.append((10, "STAFF_VLAN", "10.10.10.1/24", "10.10.10.10-10.10.10.250", "10.10.10.0/24"))
    if req.guest_wifi:
        vlans_to_create.append((20, "GUEST_VLAN", "10.20.20.1/24", "10.20.20.10-10.20.20.250", "10.20.20.0/24"))
    if req.voip_needed:
        vlans_to_create.append((30, "VOIP_VLAN", "10.30.30.1/24", "10.30.30.10-10.30.30.250", "10.30.30.0/24"))
    if req.cctv_needed:
        vlans_to_create.append((40, "CCTV_VLAN", "10.40.40.1/24", "10.40.40.10-10.40.40.250", "10.40.40.0/24"))

    config_lines.append("\n/interface vlan")
    for v_id, v_name, _, _, _ in vlans_to_create:
        config_lines.append(f"add interface=bridge name={v_name.lower()} vlan-id={v_id}")

    config_lines.append("\n/interface bridge port")
    config_lines.append("add bridge=bridge interface=ether2 pvid=10 comment=\"Staff Access Port\"")
    config_lines.append("add bridge=bridge interface=ether3 pvid=20 comment=\"Guest Access Port\"")
    config_lines.append("add bridge=bridge interface=ether4 pvid=99 comment=\"Management port\"")

    config_lines.append("\n/interface bridge vlan")
    for v_id, v_name, _, _, _ in vlans_to_create:
        config_lines.append(f"add bridge=bridge tagged=bridge,ether5 untagged=ether2 vlan-ids={v_id}")

    config_lines.append("\n/ip pool")
    for _, v_name, _, v_pool, _ in vlans_to_create:
        config_lines.append(f"add name=pool_{v_name.lower()} ranges={v_pool}")

    config_lines.append("\n/ip dhcp-server")
    for _, v_name, v_ip, _, _ in vlans_to_create:
        config_lines.append(f"add name=dhcp_{v_name.lower()} interface={v_name.lower()} address-pool=pool_{v_name.lower()} disabled=no lease-time=8h")

    config_lines.append("\n/ip address")
    for _, v_name, v_ip, _, _ in vlans_to_create:
        config_lines.append(f"add address={v_ip} interface={v_name.lower()}")

    config_lines.append("\n/ip dhcp-server network")
    for _, v_name, v_ip, _, v_subnet in vlans_to_create:
        gateway = v_ip.split("/")[0]
        config_lines.append(f"add address={v_subnet} gateway={gateway} dns-server=8.8.8.8")

    config_lines.append("\n/ip firewall filter")
    config_lines.append("add chain=input action=accept connection-state=established,related comment=\"Accept established, related\"")
    config_lines.append("add chain=input action=drop connection-state=invalid comment=\"Drop invalid\"")
    config_lines.append("add chain=input action=accept protocol=icmp comment=\"Allow ICMP ping\"")
    config_lines.append("add chain=input action=drop in-interface-list=WAN comment=\"Drop all input from WAN (BP-0003)\"")

    config_lines.append("add chain=forward action=fasttrack-connection connection-state=established,related comment=\"FastTrack\"")
    config_lines.append("add chain=forward action=accept connection-state=established,related comment=\"Accept established, related\"")
    config_lines.append("add chain=forward action=drop connection-state=invalid comment=\"Drop invalid\"")
    if req.guest_wifi:
        config_lines.append("add chain=forward action=drop in-interface=guest_vlan out-interface=!wan comment=\"Isolate Guest VLAN (BP-0001)\"")
    config_lines.append("add chain=forward action=drop connection-nat-state=!dstnat connection-state=new in-interface-list=WAN comment=\"Drop new forward from WAN\"")

    config_lines.append("\n/interface list")
    config_lines.append("add name=WAN")
    config_lines.append("add name=LAN")
    config_lines.append("\n/interface list member")
    config_lines.append("add interface=ether1 list=WAN")
    config_lines.append("add interface=bridge list=LAN")

    config_lines.append("\n/ip firewall nat")
    config_lines.append("add chain=srcnat out-interface-list=WAN action=masquerade comment=\"Masquerade WAN traffic\"")

    config_rsc = "\n".join(config_lines)

    rollback_lines = [
        "# --- Rollback Configuration ---",
        "/ip firewall nat remove [find]",
        "/interface list member remove [find]",
        "/interface list remove [find]",
        "/ip firewall filter remove [find]",
        "/ip dhcp-server network remove [find]",
        "/ip address remove [find]",
        "/ip dhcp-server remove [find]",
        "/ip pool remove [find]",
        "/interface bridge port remove [find]",
        "/interface bridge vlan remove [find]",
        "/interface vlan remove [find]",
        "/interface bridge remove [find]"
    ]
    rollback_rsc = "\n".join(rollback_lines)

    mermaid_lines = ["graph TD", "  WAN[\"🌐 Інтернет\"]", "  Router[\"🎛️ Маршрутизатор: Router-" + req.office_name + "\"]", "  WAN -->|ether1| Router"]
    for v_id, v_name, _, _, _ in vlans_to_create:
        mermaid_lines.append(f"  Router ==>|VLAN {v_id}| {v_name}[\"📶 {v_name} ({v_id})\"]")
    mermaid_code = "\n".join(mermaid_lines)

    doc_lines = [
        f"# Проект мережі: {req.office_name}",
        f"Згенеровано автоматично платформою MikroTik RouterOS Engineering Platform.",
        "",
        "## Схема підмереж та VLAN:",
        "| VLAN ID | Назва VLAN | Адреса шлюзу | Діапазон IP адрес | Призначення |",
        "| --- | --- | --- | --- | --- |"
    ]
    for v_id, v_name, v_ip, v_pool, v_subnet in vlans_to_create:
        doc_lines.append(f"| {v_id} | {v_name} | {v_ip.split('/')[0]} | {v_pool} | Мережа для {v_name.lower()} |")

    doc_lines.extend([
        "",
        "## Інструкція зі встановлення:",
        "1. Підключіться до порту ether4 або ether5 роутера MikroTik (дефолтна IP: 192.168.88.1).",
        "2. Скопіюйте вміст файлу `router.rsc` та вставте його у термінал Winbox/SSH.",
        "3. Перезавантажте пристрій для активації апаратної фільтрації VLAN на Bridge."
    ])
    doc_md = "\n".join(doc_lines)

    checklist_md = """# Чек-лист приймально-здавальних випробувань (Acceptance Checklist)
- [ ] Перевірити фізичне підключення лінку провайдера у порт ether1.
- [ ] Перевірити отримання IP-адреси по DHCP клієнтами у Staff VLAN (VLAN 10, порт ether2).
- [ ] Перевірити пінгування шлюзу 10.10.10.1 та зовнішніх сайтів (наприклад, 8.8.8.8).
- [ ] Перевірити ізоляцію гостьової мережі: запустити ping з VLAN 20 на шлюз керування 192.168.99.1 (має бути заблоковано).
- [ ] Перевірити роботу брандмауера: спробувати підключитися по Winbox з боку WAN інтерфейсу (має бути заблоковано).
"""

    inventory = {
        "office_name": req.office_name,
        "clients_count": req.clients_count,
        "generated_vlans": [v[1] for v in vlans_to_create],
        "created_at": datetime.now().isoformat()
    }

    return {
        "router_rsc": config_rsc,
        "rollback_rsc": rollback_rsc,
        "topology_mmd": mermaid_code,
        "inventory_json": inventory,
        "documentation_md": doc_md,
        "acceptance_checklist_md": checklist_md
    }

@app.post("/api/design/packet-trace")
async def packet_trace_api(req: PacketTraceRequest):
    from backend.parsers.ast_parser import RouterOS_AST
    from backend.design.migration import ReferenceResolver, DigitalTwin
    try:
        ast = RouterOS_AST.parse_rsc(req.config)
        resolved = ReferenceResolver.resolve_ast_references(ast)
        twin = DigitalTwin(resolved, ast)
        res = twin.simulate_packet_trace(
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
            protocol=req.protocol,
            dst_port=req.dst_port,
            connection_state=req.connection_state
        )
        return res
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Помилка симуляції пакету: {str(e)}"})


@app.get("/api/wiki/models")
async def get_wiki_models():
    from backend.knowledgebase.kb import RouterOSKB
    return RouterOSKB.get_models()


@app.get("/api/history")
async def get_history():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, filename, summary, issues_count, created_at FROM audit_history ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return [{"id": r[0], "filename": r[1], "summary": json.loads(r[2]), "issues_count": r[3], "created_at": r[4]} for r in rows]

@app.get("/api/knowledge")
async def get_knowledge():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, problem, solution, tags, created_at, used_count FROM knowledge ORDER BY used_count DESC, created_at DESC"
    ).fetchall()
    conn.close()
    return [{"id": r[0], "problem": r[1], "solution": r[2], "tags": r[3], "created_at": r[4], "used_count": r[5]} for r in rows]

@app.post("/api/knowledge")
async def add_knowledge(entry: KnowledgeEntry):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO knowledge (problem, solution, tags) VALUES (?,?,?)",
        (entry.problem, entry.solution, entry.tags)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.delete("/api/knowledge/{kid}")
async def delete_knowledge(kid: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM knowledge WHERE id=?", (kid,))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.get("/api/knowledge/use/{kid}")
async def use_knowledge(kid: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE knowledge SET used_count=used_count+1 WHERE id=?", (kid,))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.post("/api/report/generate")
async def generate_report(req: AnalyzeRequest):
    result = full_audit(req.config)

    report = []
    report.append("==========================================================================")
    report.append("             ЗВІТ ПРО АУДИТ КОНФІГУРАЦІЇ MIKROTIK ROUTEROS               ")
    report.append("==========================================================================")
    report.append(f"Файл конфігурації: {req.filename or 'config.rsc'}")
    report.append(f"Дата генерації: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Загальний бал готовності (Production Readiness Score): {result['production_readiness']['score']}%")
    report.append(f"Вердикт: {'ГОТОВИЙ ДО ЕКСПЛУАТАЦІЇ' if result['production_readiness']['verdict'] == 'READY' else 'НЕ ГОТОВИЙ ДО ЕКСПЛУАТАЦІЇ'}")
    report.append("==========================================================================\n")

    # 1. EXECUTIVE SUMMARY
    report.append("1. EXECUTIVE SUMMARY (РЕЗЮМЕ ДЛЯ КЕРІВНИЦТВА)")
    report.append("--------------------------------------------------------------------------")
    report.append(f"Аудит мережі MikroTik виявив {result['summary']['total_issues']} критичних/високих помилок та {result['summary']['total_warnings']} попереджень.")
    report.append(f"Поточний статус готовності до продакшну оцінюється у {result['production_readiness']['score']}%.")
    if result['production_readiness']['critical_failures']:
        report.append("Критичні фактори, що блокують запуск мережі в експлуатацію:")
        for cf in result['production_readiness']['critical_failures']:
            report.append(f"  - {cf}")
    else:
        report.append("Усі життєво важливі служби мережі (NAT, WAN, міст) налаштовані та працездатні.")
    report.append("\n")

    # 2. CRITICAL ISSUES
    report.append("2. CRITICAL ISSUES (КРИТИЧНІ ПОМИЛКИ)")
    report.append("--------------------------------------------------------------------------")
    if result['production_readiness']['critical_failures']:
        for c in result['production_readiness']['critical_failures']:
            report.append(f" [CRITICAL] {c}")
    else:
        report.append("Критичних помилок не виявлено.")
    report.append("\n")

    # 3. HIGH ISSUES
    report.append("3. HIGH ISSUES (ПОМИЛКИ ВИСОКОГО ПРІОРИТЕТУ)")
    report.append("--------------------------------------------------------------------------")
    highs = []
    sections_to_check = ["l2", "vlan_ext", "dhcp_ext", "capsman_ext", "wifi_ext", "firewall", "multiwan", "script", "services", "performance_ext", "orphan_objects"]
    for sect_key in sections_to_check:
        sect = result.get(sect_key)
        if sect and sect.get("issues"):
            for issue in sect["issues"]:
                highs.append(issue)

    if highs:
        for h in set(highs):
            report.append(f" [HIGH] {h}")
    else:
        report.append("Помилок високого пріоритету не виявлено.")
    report.append("\n")

    # 4. WARNINGS
    report.append("4. WARNINGS (ПОПЕРЕДЖЕННЯ)")
    report.append("--------------------------------------------------------------------------")
    warns = []
    for sect_key in sections_to_check:
        sect = result.get(sect_key)
        if sect and sect.get("warnings"):
            for w in sect["warnings"]:
                warns.append(w)

    if warns:
        for w in set(warns):
            report.append(f" [WARNING] {w}")
    else:
        report.append("Попереджень не виявлено.")
    report.append("\n")

    # 5. RECOMMENDATIONS
    report.append("5. RECOMMENDATIONS (РЕКОМЕНДАЦІЇ З ОПТИМІЗАЦІЇ)")
    report.append("--------------------------------------------------------------------------")
    recs = []
    for sect_key in sections_to_check:
        sect = result.get(sect_key)
        if sect and sect.get("recommendations"):
            for r in sect["recommendations"]:
                recs.append(r)
        if sect and sect.get("fixes"):
            for f in sect["fixes"]:
                recs.append(f"Застосувати виправлення: {f}")

    if recs:
        for r in set(recs):
            report.append(f" [*] {r}")
    else:
        report.append("Рекомендацій з оптимизації не сформовано.")
    report.append("\n")

    # 6. SECURITY REPORT
    report.append("6. SECURITY REPORT (ДЕТАЛЬНИЙ ЗВІТ БЕЗПЕКИ)")
    report.append("--------------------------------------------------------------------------")
    report.append(f"Рівень безпеки (Security Rating): {result['security_ext']['score']}/100")
    report.append("\n")

    # 7. TOPOLOGY REPORT
    report.append("7. TOPOLOGY REPORT (АНАЛІЗ ТОПОЛОГІЇ МЕРЕЖІ)")
    report.append("--------------------------------------------------------------------------")
    if result.get("topology") and result["topology"].get("chains"):
        for chain in result["topology"]["chains"]:
            report.append(f" Мережа: {chain['network']} - Status: {chain['status'].upper()}")
            steps_str = " -> ".join(s['name'] for s in chain['chain_steps'])
            report.append(f"  Ланцюг: {steps_str}")
            for step in chain['chain_steps']:
                if step['status'] != 'ok':
                    report.append(f"    * Помилка на кроці '{step['name']}': {step['detail']}")
    else:
        report.append("Топологічний звіт недоступний.")
    report.append("\n")

    # 8. PRODUCTION READINESS SCORE
    report.append("8. PRODUCTION READINESS SCORE (КЛЮЧОВІ ПОКАЗНИКИ ГОТОВНОСТІ)")
    report.append("--------------------------------------------------------------------------")
    report.append(f"Підсумковий індекс готовності: {result['production_readiness']['score']}%")
    report.append("Розподіл за категоріями:")
    for cat, score in result["production_readiness"]["breakdown"].items():
        report.append(f"  - {cat.upper()}: {score}%")
    report.append("\n==========================================================================")

    return {"report": "\n".join(report)}

@app.get("/api/report/{history_id}")
async def get_report(history_id: int):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT filename, summary, issues_count, created_at FROM audit_history WHERE id=?",
        (history_id,)
    ).fetchone()
    conn.close()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Звіт не знайдено"})

    filename, summary_str, issues_count, created_at = row
    summary = json.loads(summary_str)

    report = []
    report.append("==================================================")
    report.append(f"ЗВІТ ПРО АУДИТ КОНФІГУРАЦІЇ MIKROTIK")
    report.append("==================================================")
    report.append(f"Файл: {filename or 'config'}")
    report.append(f"Дата аудиту: {created_at}")
    report.append(f"Оцінка готовності: {summary.get('score', 0)}/100")
    report.append(f"Критичні проблеми: {summary.get('total_issues', 0)}")
    report.append(f"Попередження: {summary.get('total_warnings', 0)}")
    report.append("==================================================")
    report.append("\nЦей звіт сформовано на основі історії аудиту.")

    return {"report": "\n".join(report)}

@app.post("/api/compliance")
async def check_compliance(req: AnalyzeRequest):
    policy = load_policy()
    if not policy:
        return {"violations": [], "passed": [], "compliant": True, "score": None, "note": "Регламент не налаштовано"}
    model = parse_to_model(req.config)
    result = audit_compliance(model, policy)
    return result

@app.get("/api/policy")
async def get_policy():
    return load_policy()

@app.post("/api/policy")
async def set_policy(policy: dict):
    save_policy(policy)
    return {"status": "ok"}

@app.get("/api/sample-config")
async def get_sample_config():
    config = """# model = hAP ax3
/system identity
set name=Router-Home

/interface bridge
add name=bridge vlan-filtering=no comment="Main local bridge"

/interface vlan
add interface=bridge name=vlan10_mgmt vlan-id=10
add interface=bridge name=vlan20_staff vlan-id=20

/interface bridge port
add bridge=bridge interface=ether2 pvid=20 comment="Staff Access Port"
add bridge=bridge interface=ether3 pvid=30 comment="Guest Access Port"

/interface bridge vlan
add bridge=bridge tagged=bridge,ether5 untagged=ether2 vlan-ids=20

/ip address
add address=10.20.0.1/24 interface=vlan20_staff

/ip pool
add name=pool_staff ranges=10.20.0.10-10.20.0.200

/ip dhcp-server
add name=dhcp_staff interface=vlan20_staff address-pool=pool_staff disabled=no lease-time=8h

/ip dhcp-server network
add address=10.20.0.0/24 gateway=10.20.0.1 dns-server=8.8.8.8

/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
set winbox port=8291 disabled=no

/ip neighbor discovery-settings
set discover-interface-list=all
"""
    return {"config": config}

@app.get("/", response_class=FileResponse)
async def root():
    return FileResponse(STATIC_DIR / "index.html")

app.mount("/", StaticFiles(directory=STATIC_DIR), name="static")

# ─── Launch ──────────────────────────────────────────────────────────────────

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://localhost:8899")

if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8899, log_level="warning")
