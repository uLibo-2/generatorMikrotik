# -*- coding: utf-8 -*-
"""
RouterOS Config Preprocessor & Normalizer
"""
import re
from typing import List, Dict, Any, Tuple

def join_backslashes(text: str) -> List[str]:
    """Joins lines ending with a backslash into a single line."""
    raw_lines = text.splitlines()
    joined_lines = []
    current_line = ""

    for line in raw_lines:
        trimmed = line.strip()
        if trimmed.endswith("\\"):
            current_line += " " + trimmed[:-1].strip()
        else:
            current_line += " " + trimmed
            joined_lines.append(current_line.strip())
            current_line = ""

    if current_line:
        joined_lines.append(current_line.strip())

    return [l for l in joined_lines if l]

def tokenize_command_params(param_str: str) -> Tuple[str, Dict[str, str]]:
    """
    Parses parameter string into a finder query block and key-value parameters.
    Handles quote escapes and spaces.
    Example: '[ find default-name=ether1 ] comment="ISP1" disabled=no'
    Returns: ('[ find default-name=ether1 ]', {'comment': 'ISP1', 'disabled': 'no'})
    """
    finder = ""
    params = {}

    # 1. Extract find/search blocks if they exist, e.g. [ find default-name=ether1 ] or [ find ]
    finder_match = re.search(r'\[\s*find\s+.*?\]|\[\s*find\s*\]', param_str)
    if finder_match:
        finder = finder_match.group(0)
        # Remove finder block from parameter list
        param_str = param_str.replace(finder, " ")

    # 2. Tokenize key-value parameters
    # State machine to handle quotes
    tokens = []
    current_token = ""
    in_quotes = False
    escape = False

    for char in param_str:
        if escape:
            current_token += char
            escape = False
        elif char == '\\':
            escape = True
        elif char == '"':
            in_quotes = not in_quotes
            current_token += char
        elif char.isspace() and not in_quotes:
            if current_token:
                tokens.append(current_token)
                current_token = ""
        else:
            current_token += char

    if current_token:
        tokens.append(current_token)

    # 3. Parse tokens into key-value pairs
    for token in tokens:
        if "=" in token:
            k, v = token.split("=", 1)
            params[k.strip()] = v.strip()
        else:
            # Bare flag parameter, e.g. disabled or enabled
            params[token.strip()] = ""

    return finder, params

def normalize_command_line(line: str) -> str:
    """
    Standardizes a single RouterOS command.
    Example: 'add interface=bridge address=10.0.0.1/24'
    ➔ 'add address=10.0.0.1/24 interface=bridge'
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return line

    # Check if command is a section header, e.g. /ip address
    if line.startswith("/"):
        # Normalize spaces inside path
        return re.sub(r'\s+', ' ', line)

    # Parse action word (add, set, remove, enable, disable)
    action_match = re.match(r'^([a-zA-Z\-]+)\b', line)
    if not action_match:
        return line

    action = action_match.group(1)
    param_part = line[action_match.end():].strip()

    finder, params = tokenize_command_params(param_part)

    # Reassemble parameters sorted alphabetically
    sorted_params = []
    for k in sorted(params.keys()):
        v = params[k]
        if v:
            sorted_params.append(f"{k}={v}")
        else:
            sorted_params.append(k)

    param_str = " ".join(sorted_params)

    parts = [action]
    if finder:
        # Standardize spaces in finder block
        clean_finder = re.sub(r'\s+', ' ', finder)
        parts.append(clean_finder)
    if param_str:
        parts.append(param_str)

    return " ".join(parts)

def normalize_rsc(config_text: str) -> List[str]:
    """Preprocesses and normalizes a full RSC export."""
    lines = join_backslashes(config_text)
    normalized = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            # Keep comments for maintainability
            normalized.append(line)
        else:
            normalized.append(normalize_command_line(line))

    return normalized
