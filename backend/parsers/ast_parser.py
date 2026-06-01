# -*- coding: utf-8 -*-
"""
RouterOS Config AST Parser
"""
import re
from typing import List, Dict, Any, Tuple
from backend.parsers.normalizer import normalize_rsc, tokenize_command_params

# List of known RouterOS action words
ROS_ACTIONS = {"add", "set", "remove", "enable", "disable", "edit", "reset", "export", "print", "move"}

class ASTNode:
    """Represents a single parsed RouterOS command statement."""
    def __init__(self, path: str, action: str, finder: str = "", params: Dict[str, str] = None, comment: str = ""):
        self.path = path  # e.g., "/ip address"
        self.action = action  # e.g., "add", "set"
        self.finder = finder  # e.g., "[ find default-name=ether1 ]"
        self.params = params or {}  # e.g., {"address": "10.0.0.1/24", "interface": "bridge-work"}
        self.comment = comment  # Any associated inline or preceding comments

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "action": self.action,
            "finder": self.finder,
            "params": self.params,
            "comment": self.comment
        }

    def __repr__(self) -> str:
        return f"ASTNode({self.path} {self.action} {self.finder} {self.params})"

class RouterOS_AST:
    """Holds the collection of parsed AST nodes representing the RouterOS script."""
    def __init__(self):
        self.nodes: List[ASTNode] = []

    @classmethod
    def parse_rsc(cls, config_text: str) -> "RouterOS_AST":
        ast = cls()
        normalized_lines = normalize_rsc(config_text)

        current_path = ""
        pending_comment = ""

        for line in normalized_lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Handle comment lines
            if line_str.startswith("#"):
                # Accumulate multi-line comments
                pending_comment += line_str + "\n"
                continue

            # Check if line contains a section change or inline command
            if line_str.startswith("/"):
                # Check for inline action, e.g. /ip service set telnet disabled=yes
                parts = line_str.split(" ")
                action_idx = -1
                for idx, part in enumerate(parts):
                    if part.lower() in ROS_ACTIONS:
                        action_idx = idx
                        break

                if action_idx != -1:
                    # Inline command
                    path = " ".join(parts[:action_idx])
                    action = parts[action_idx]
                    param_part = " ".join(parts[action_idx + 1:])

                    finder, params = tokenize_command_params(param_part)

                    ast.nodes.append(ASTNode(
                        path=path,
                        action=action,
                        finder=finder,
                        params=params,
                        comment=pending_comment.strip()
                    ))
                    current_path = path  # Update context path
                    pending_comment = ""
                else:
                    # Plain path context change, e.g. /ip address
                    current_path = line_str
                    pending_comment = ""
                continue

            # Check for standard action commands in current path context
            action_match = re.match(r'^([a-zA-Z\-]+)\b', line_str)
            if action_match and action_match.group(1).lower() in ROS_ACTIONS:
                action = action_match.group(1)
                param_part = line_str[action_match.end():].strip()

                finder, params = tokenize_command_params(param_part)

                ast.nodes.append(ASTNode(
                    path=current_path,
                    action=action,
                    finder=finder,
                    params=params,
                    comment=pending_comment.strip()
                ))
                pending_comment = ""
            else:
                # Unrecognized statements, keep as raw text or default to set/add if appropriate
                # E.g. inline scripts or direct terminal calls.
                if current_path:
                    ast.nodes.append(ASTNode(
                        path=current_path,
                        action="raw",
                        params={"text": line_str},
                        comment=pending_comment.strip()
                    ))
                    pending_comment = ""

        return ast

    def to_list(self) -> List[Dict[str, Any]]:
        return [node.to_dict() for node in self.nodes]
