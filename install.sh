#!/usr/bin/env bash
# find-evil: add the iocflow IOC-lifecycle layer to a Protocol SIFT install.
#
# Idempotent. Run AFTER protocol-sift's own install.sh, on the SIFT Workstation:
#   curl -fsSL https://raw.githubusercontent.com/vinayvobbili/find-evil/main/install.sh | bash
#
# It installs iocflow (with the MCP extra), registers the iocflow MCP server with
# Claude Code, and drops the ioc-lifecycle skill next to Protocol SIFT's skills.
set -euo pipefail

CLAUDE_DIR="${CLAUDE_DIR:-$HOME/.claude}"
SKILLS_DIR="$CLAUDE_DIR/skills/ioc-lifecycle"
RAW="https://raw.githubusercontent.com/vinayvobbili/find-evil/main"

echo "[find-evil] installing iocflow[mcp] + domainflow ..."
python3 -m pip install --user --upgrade "iocflow[mcp]" domainflow >/dev/null

echo "[find-evil] installing actor-pivot MCP server -> $CLAUDE_DIR/find-evil/mcp_pivot"
PIVOT_DIR="$CLAUDE_DIR/find-evil/mcp_pivot"
mkdir -p "$PIVOT_DIR"
if [ -f "mcp_pivot/server.py" ]; then
  cp "mcp_pivot/server.py" "$PIVOT_DIR/server.py"
else
  curl -fsSL "$RAW/mcp_pivot/server.py" -o "$PIVOT_DIR/server.py"
fi

echo "[find-evil] installing ioc-lifecycle skill -> $SKILLS_DIR"
mkdir -p "$SKILLS_DIR"
if [ -f "skills/ioc-lifecycle/SKILL.md" ]; then
  cp "skills/ioc-lifecycle/SKILL.md" "$SKILLS_DIR/SKILL.md"
else
  curl -fsSL "$RAW/skills/ioc-lifecycle/SKILL.md" -o "$SKILLS_DIR/SKILL.md"
fi

echo "[find-evil] registering iocflow MCP server with Claude Code ..."
# Prefer the CLI so it merges cleanly with protocol-sift's own config.
if command -v claude >/dev/null 2>&1; then
  claude mcp add iocflow -- iocflow-mcp 2>/dev/null \
    || echo "[find-evil] 'iocflow' MCP server already registered — skipping"
  claude mcp add domainflow-pivot -- python3 "$PIVOT_DIR/server.py" 2>/dev/null \
    || echo "[find-evil] 'domainflow-pivot' MCP server already registered — skipping"
else
  echo "[find-evil] 'claude' CLI not found; writing $CLAUDE_DIR/.mcp.json"
  cat > "$CLAUDE_DIR/.mcp.json" <<JSON
{ "mcpServers": {
  "iocflow": { "command": "iocflow-mcp", "args": [], "env": {} },
  "domainflow-pivot": { "command": "python3", "args": ["$PIVOT_DIR/server.py"], "env": {} }
} }
JSON
fi

echo "[find-evil] done. Start Protocol SIFT and the agent will have the iocflow + pivot tools."
echo "[find-evil] verify: claude mcp list   (expect: iocflow, domainflow-pivot)"
