# MORDOR Skill: Caveman Token Compression

Skill: `caveman` (output compression), `caveman-shrink` (MCP middleware).
Installed: `npx skills add JuliusBrussee/caveman --yes` → 8 skills.
MCP: All MORDOR servers wrapped via `caveman-shrink` in `mcp_config/claude_desktop_config.json`.

Cuts agent output tokens ~65% and MCP tool descriptions ~60% without losing technical accuracy.

## Installed Skills

| Skill | Function |
|-------|----------|
| `caveman` | Output compression — `/caveman lite/full/ultra` |
| `caveman-compress` | Compress input files (CLAUDE.md, docs) |
| `caveman-shrink` | MCP middleware — wraps servers, compresses tool descriptions |
| `caveman-commit` | Terse commit msg: ≤50 char subject |
| `caveman-review` | One-line PR review: `L42: 🔴 bug: null guard` |
| `caveman-stats` | Token savings report + lifetime stats |
| `caveman-help` | Quick reference card |
| `cavecrew` | Caveman subagents (investigator, builder, reviewer) |

## MCP Integration

All 5 MCP servers wrapped with `caveman-shrink`:

|cavan | Original | Wrapped |
|-------|----------|---------|
| ghidra | `python ...bridge_mcp_ghidra.py` | `npx caveman-shrink python bridge_mcp_ghidra.py` |
| radare2 | `r2mcp` | `npx caveman-shrink r2mcp` |
| pay | `pay mcp` | `npx caveman-shrink pay mcp` |
| filesystem | `python3 -m mcp_server_filesystem` | `npx caveman-shrink python3 -m mcp_server_filesystem` |
| shodan | `npx -y @modelcontextprotocol/server-shodan` | `npx caveman-shrink npx -y server-shodan` |

## Pipeline Impact

| Phase | Impact |
|-------|--------|
| Context load | MCP tool descriptions 60% shorter → more room for case data |
| Agent reasoning | Non-critical agents (BOROMIR, GOLLUM, CELEBORN) use caveman style for internal logs |
| Report | GANDALF_WHITE full English output for final report (caveman not applied to human-facing output) |
| Session cost | ~65% fewer output tokens per agent call |

## Configuration

All MCP servers live in `mcp_config/claude_desktop_config.json`.
Agent prompts can enable caveman mode per-agent in `agents/fellowship/*.py`.
