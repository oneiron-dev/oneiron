#!/usr/bin/env python3
"""Generate/check the Memory Wire agent mirror from the shipped SDK contract."""
from pathlib import Path
import argparse
import re
import json

ROOT = Path(__file__).resolve().parents[3]

def artifacts():
    readme = (ROOT / "packages/oneiron/README.md").read_text()
    ts = (ROOT / "packages/oneiron/src/types.ts").read_text()
    py = (ROOT / "crates/oneiron-py/python/oneiron/__init__.pyi").read_text()
    manifest = json.loads((ROOT / "scripts/sdk/agent-verbs.json").read_text())
    verbs = [row["name"] for row in manifest["verbs"] if row.get("context", "memory") == "memory"]
    errors = (ROOT / "crates/oneiron/src/memory/error.rs").read_text()
    codes = re.findall(r'pub const MEMORY_CODE_\w+: &str = "([A-Z_]+)";', errors)
    remedies = {
        "BAD_REQUEST": "Correct input fields, types and units. Timestamps are Unix seconds.",
        "NOT_FOUND": "Refresh the identifier and current read scope before retrying.",
        "FORBIDDEN": "Respect the gate or identity refusal. Review pending consent; do not widen scope or retry blindly.",
        "INVALID_STATE": "Read the current lifecycle head, then make a new decision. Do not replay a stale target.",
        "INTERNAL_SERVER_ERROR": "Check the server endpoint, network and health. Report reproducible SDK boundary failures.",
        "LEASE_REQUIRED": "Use standard/minimal recall or acquire a lease through the engine's budget door.",
        "OFF_RECORD_SESSION_DOOR": "Use the owning off-record session handle. The canonical witness door is not that handle.",
        "OWNER_BINDING_REQUIRED": "An owner device must bind this human actor in the authority log. Scope changes do not grant ownership.",
        "VAULT_LOCKED_SINGLE_WRITER": "Connect to the process that owns this vault. Do not remove lock files or open a second writer.",
    }
    if set(codes) != remedies.keys():
        raise ValueError("Document remediation for each added/removed SDK error code")
    error_doc = "# Memory Wire typed errors\n\nEvery SDK failure carries `code`, `message`, and nonempty `suggestions`.\nUse the returned suggestions; do not parse message prose. No adapter swallows\nor downgrades the engine's refusal. Future remote codes pass through verbatim.\n\n| Code | Response |\n|---|---|\n"
    error_doc += "".join(f"| `{code}` | {remedies[code]} |\n" for code in codes)
    error_doc += "\nRemote server-specific codes and HTTP schemas are also indexed by\n[the engine API reference](../../oneiron.skills.md).\n"
    census = "# Memory Wire facade census\n\nThis is the complete **shipped SDK facade**, in manifest order. It is\nnot a claim that every engine-internal method is a public SDK verb.\n`scripts/sdk/agent-verbs.json` owns this list.\nNames are stable: a new export or rename must update the engine catalog,\nboth bindings and their export-census tests in one reviewed change.\n\n"
    census += "\n".join(f"- `{verb}`" for verb in verbs) + "\n"
    return {
        "docs/agent-sdk/quickstart.md": readme,
        "docs/agent-sdk/types.md": "# Memory Wire type contract\n\n## JavaScript / TypeScript\n\n```ts\n" + ts + "```\n\n## Python\n\n```python\n" + py + "```\n",
        "docs/agent-sdk/errors.md": error_doc,
        "docs/agent-sdk/verbs.md": census,
        "llms.txt": "# Oneiron — Memory Wire\n\n> Actor-bound memory for agents. Start with witness, recall and receipts.\n> The mirror below is full fidelity, generated from shipped SDK sources.\n\n## Memory Wire SDK\n\n- [Complete quickstarts and API](docs/agent-sdk/quickstart.md): JS/Python, embedded/remote, complete imports and typed errors.\n- [Type declarations](docs/agent-sdk/types.md): full TypeScript DTOs and Python stubs.\n- [Error catalogue](docs/agent-sdk/errors.md): stable codes, suggestions and remediation.\n- [Verb census](docs/agent-sdk/verbs.md): authoritative shipped facade and stable names.\n- [Vercel AI SDK tools](packages/oneiron-ai-sdk/README.md): thin three-verb satellite and runnable agent sample.\n- [LangGraph BaseStore](packages/oneiron-langgraph/README.md): exact actor-owned long-term keyed memory, not checkpoints.\n- [HTTP API](oneiron.skills.md): endpoint activation index, endpoint details and error schemas.\n",
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for name, contents in artifacts().items():
        path = ROOT / name
        if path.exists() and path.read_text() == contents:
            continue
        if args.check:
            stale.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
    if stale:
        raise SystemExit("SDK-MIRROR-STALE: " + ", ".join(stale))
