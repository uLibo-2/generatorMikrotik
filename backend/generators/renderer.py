# -*- coding: utf-8 -*-
"""
RouterOS Config Renderer / Compiler
"""
from backend.parsers.ast_parser import RouterOS_AST, ASTNode

def render_ast(ast: RouterOS_AST) -> str:
    """
    Renders a RouterOS AST structure back to a standard RouterOS .rsc config file.
    Groups consecutive statements belonging to the same section context.
    """
    lines = []
    current_path = ""

    for node in ast.nodes:
        # 1. Output any associated comments
        if node.comment:
            lines.append(node.comment)

        # 2. Output section header if path context changed
        if node.path and node.path != current_path:
            # If path context is just "raw", we don't output path
            if node.action != "raw" or not node.path.startswith("/"):
                lines.append(node.path)
                current_path = node.path

        # 3. Output command body
        if node.action == "raw":
            # For raw strings (unrecognized scripts/lines), output directly
            lines.append(node.params.get("text", ""))
            continue

        # Compile parameters key=value
        param_parts = []
        for k, v in node.params.items():
            if v:
                param_parts.append(f"{k}={v}")
            else:
                param_parts.append(k)

        param_str = " ".join(param_parts)

        parts = [node.action]
        if node.finder:
            parts.append(node.finder)
        if param_str:
            parts.append(param_str)

        command_line = " ".join(parts)

        # If no path is specified but we have a command, render it (e.g. standalone scripts)
        # Indent sub-statements slightly for premium readablity (or keep flat ROS standard)
        # Flat ROS standard is standard, but indentation can be customized
        lines.append(command_line)

    return "\n".join(lines)
