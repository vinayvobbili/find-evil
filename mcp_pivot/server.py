"""find-evil actor-pivot MCP server — one secondary tool over domainflow.

This is the *optional breadth* layer. The core lifecycle is the iocflow MCP server
(extract / reconcile / hunt). This server adds a single correlation step: once the
agent has extracted domains from forensic evidence, it can pivot those domains into
the actor's wider infrastructure by clustering on shared, *discriminating* pivots.

Read-only and offline: no network, no shell, no writes. Like the rest of find-evil,
the dangerous verbs simply do not exist as tools.

Run (stdio transport):

    python3 mcp_pivot/server.py        # from the find-evil repo
    # registered on the SIFT box by install.sh as the 'domainflow-pivot' MCP server

Needs: pip install domainflow  and  pip install 'mcp>=1.2'
"""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass


def cluster_actor_infrastructure(findings_json: str) -> dict:
    """Cluster enriched domain findings into actor campaigns by shared infrastructure.

    Call this AFTER extracting domains from evidence (e.g. C2/phishing domains surfaced by
    iocflow's extract_iocs) to answer: "do these domains belong to one actor's campaign?"

    Input: a JSON array of finding objects. Each object should carry at least ``domain`` and,
    when known, ``ip_addresses`` (list), ``registrant_org`` (str), and ``nameservers`` (list).
    Clustering only joins on *discriminating* pivots and suppresses values too common to mean
    anything (bulk registrars, Let's Encrypt, Cloudflare), so a cluster reflects a genuinely
    linked set of registrations rather than one giant blob.

    Returns ``{"campaigns": [...], "count": N}`` where each campaign lists its size, the pivots
    that link it, and its domains. Read-only; performs no network lookups.
    """
    from domainflow import cluster_campaigns

    findings = json.loads(findings_json)
    if not isinstance(findings, list):
        return {"error": "findings_json must be a JSON array of finding objects", "campaigns": [], "count": 0}

    campaigns = cluster_campaigns(findings)
    out = []
    for c in campaigns:
        if is_dataclass(c):
            out.append(asdict(c))
        elif hasattr(c, "to_dict"):
            out.append(c.to_dict())
        else:  # last-resort best effort
            out.append({"size": getattr(c, "size", None), "domains": list(getattr(c, "domains", []))})
    return {"campaigns": out, "count": len(out)}


def main() -> int:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("domainflow-pivot MCP server needs the mcp SDK: pip install 'mcp>=1.2'") from exc

    server = FastMCP("domainflow-pivot")
    server.add_tool(cluster_actor_infrastructure)
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
