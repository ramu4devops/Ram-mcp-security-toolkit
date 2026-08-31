#!/usr/bin/env python3
"""
static_extract.py -- pull MCP tool definitions straight out of Python source
using the standard library `ast` module. No execution of the target code,
no network, no dependencies beyond Python itself.

Recognizes the common decorator patterns from the official Python MCP SDK:
    @mcp.tool()
    def my_tool(...): ...   (docstring becomes the tool description)
    @server.tool(name="...", description="...")

Usage: python static_extract.py path/to/repo > tools.json
"""
import ast, sys, json, os

TOOL_DECORATOR_NAMES = {"tool"}   # matches @mcp.tool / @server.tool / @app.tool

def is_tool_decorator(dec):
    # handles both @mcp.tool and @mcp.tool(...)
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute):
        return node.attr in TOOL_DECORATOR_NAMES
    return False

def extract_from_file(path):
    tools = []
    try:
        tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    except SyntaxError:
        return tools
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if is_tool_decorator(dec):
                doc = ast.get_docstring(node) or ""
                params = {}
                required = []
                for arg in node.args.args:
                    if arg.arg == "self":
                        continue
                    params[arg.arg] = {"type": "string"}   # simplified typing
                    required.append(arg.arg)
                tools.append({
                    "name": node.name,
                    "description": doc,
                    "input_schema": {"type": "object", "properties": params,
                                     "required": required},
                    "source_ref": f"{path}:{node.lineno}",
                })
                break
    return tools

def main(root):
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".py"):
                out += extract_from_file(os.path.join(dirpath, f))
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
