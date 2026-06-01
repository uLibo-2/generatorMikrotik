import re
from typing import Optional, List, Dict
from backend.models.network_model import NetworkModel

def clean_comment_and_join_lines(config: str) -> Dict[str, List[str]]:
    sections = {}
    current = None
    lines = config.splitlines()

    joined_lines = []
    temp_line = ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            temp_line += stripped[:-1].rstrip() + " "
        else:
            if temp_line:
                joined_lines.append(temp_line + stripped)
                temp_line = ""
            else:
                joined_lines.append(stripped)
    if temp_line:
        joined_lines.append(temp_line)

    for line in joined_lines:
        if line.startswith("/"):
            # Check if this is a flat command containing ROS action verbs
            actions = [" add ", " set ", " remove ", " disable ", " enable ", " print ", " find "]
            action_found = None
            for action in actions:
                if action in line:
                    action_found = action
                    break

            if action_found:
                parts = line.split(action_found, 1)
                current = parts[0].strip()
                if current not in sections:
                    sections[current] = []
                sections[current].append(action_found.strip() + " " + parts[1].strip())
            else:
                current = line
                if current not in sections:
                    sections[current] = []
        elif current:
            sections[current].append(line)
    return sections

def get_param_value(line: str, param: str) -> Optional[str]:
    # Match param="value" (handling double quotes)
    match = re.search(fr'{re.escape(param)}="([^"]*)"', line)
    if match:
        return match.group(1)
    # Match param=value (stopping at whitespace or end of line)
    match = re.search(fr'{re.escape(param)}=([^\s]+)', line)
    if match:
        return match.group(1)
    return None

def get_section(sections: dict, path: str) -> list:
    norm = lambda p: " ".join(p.lower().replace("/", " ").replace("\\", " ").split())
    target = norm(path)
    for k, v in sections.items():
        if norm(k) == target:
            return v
    return []

def detect_routeros_version(config: str) -> dict:
    # Scan first 20 lines for header comment with version
    lines = config.splitlines()[:20]
    version = "7.20"
    major = 7
    for line in lines:
        if "by RouterOS" in line:
            match = re.search(r"by RouterOS (\d+)\.(\d+)(?:\.(\d+))?", line)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                patch = match.group(3) or "0"
                version = f"{major}.{minor}.{patch}"
                break
    return {"version": version, "major": major}

def detect_hardware(config: str) -> str:
    """Detect MikroTik hardware model from config comments or interface names."""
    lines = config.splitlines()[:30]
    # Primary: look for "# model = <model>" comment in header
    for line in lines:
        if "model =" in line or "model=" in line:
            match = re.search(r"model\s*=\s*[\"']?([\w\s.-]+)[\"']?", line)
            if match:
                return match.group(1).strip().strip('"\'\' ')
    # Secondary: scan for RouterOS system identity or known hardware strings in full config
    identity_match = re.search(r"/system identity\s+set name=[\"\']?([^\"\'\s]+)", config)
    if identity_match:
        pass  # system identity is the router name, not the model
    # Keyword scan for known hardware
    hardware_keywords = [
        ("hAP ax3", "hAP ax3"), ("hAP ax2", "hAP ax2"), ("hAP ax", "hAP ax"),
        ("RB5009", "RB5009UG"), ("CRS326", "CRS326-24G"), ("CRS354", "CRS354"),
        ("CRS317", "CRS317"), ("CCR2004", "CCR2004"), ("CCR2116", "CCR2116"),
        ("CCR1072", "CCR1072"), ("CCR1036", "CCR1036"), ("RB4011", "RB4011"),
        ("RB3011", "RB3011"), ("RB2011", "RB2011"), ("hEX", "hEX"),
        ("wAP", "wAP"), ("cAP", "cAP ax"), ("mAP", "mAP"),
    ]
    for keyword, model in hardware_keywords:
        if keyword in config:
            return model
    return "Unknown MikroTik Device"
