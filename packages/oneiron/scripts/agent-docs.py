#!/usr/bin/env python3
"""Generate/check the Memory Wire agent mirror from the shipped SDK contract."""
from pathlib import Path
import argparse
import os
import re
import json

ROOT = Path(__file__).resolve().parents[3]

def mirrored(markdown, source, target):
    """Rewrites each relative link of `source` so it resolves from `target`."""
    def relink(match):
        link = match.group(1)
        if re.match(r"[a-z][a-z0-9+.-]*:|#|/", link):
            return match.group(0)
        path, anchor = (link.split("#", 1) + [""])[:2]
        moved = os.path.relpath(os.path.normpath(os.path.join(os.path.dirname(source), path)), os.path.dirname(target))
        return "](" + moved + ("#" + anchor if anchor else "") + ")"
    return re.sub(r"\]\(([^)\s]+)\)", relink, markdown)

def artifacts():
    readme = (ROOT / "packages/oneiron/README.md").read_text()
    ts = (ROOT / "packages/oneiron/src/types.ts").read_text()
    py = (ROOT / "crates/oneiron-py/python/oneiron/__init__.pyi").read_text()
    manifest = json.loads((ROOT / "scripts/sdk/agent-verbs.json").read_text())
    verbs = [row["name"] for row in manifest["verbs"] if row.get("context", "memory") == "memory"]
    errors = (ROOT / "crates/oneiron-contracts/src/memory/error.rs").read_text()
    codes = re.findall(r'pub const MEMORY_CODE_\w+: &str = "([A-Z_]+)";', errors)
    remedies = {
        "BAD_REQUEST": "Correct input fields, types and units. Timestamps are Unix seconds.",
        "NOT_FOUND": "Refresh the identifier and current read scope before retrying.",
        "FORBIDDEN": "Respect the gate or identity refusal. Review pending consent; do not widen scope or retry blindly.",
        "INVALID_STATE": "Read the current lifecycle head, then make a new decision. Do not replay a stale target.",
        "INTERNAL_SERVER_ERROR": "Check the server endpoint, network and health. Report reproducible SDK boundary failures.",
        "LEASE_REQUIRED": "Use light or medium recall, or present a budget lease.",
        "OFF_RECORD_SESSION_DOOR": "Use the owning off-record session handle. The canonical witness door is not that handle.",
        "OWNER_BINDING_REQUIRED": "An owner device must bind this human actor in the authority log. Scope changes do not grant ownership.",
        "VAULT_LOCKED_SINGLE_WRITER": "Connect to the process that owns this vault. Do not remove lock files or open a second writer.",
        "INVENTED_REFERENCE": "Name only records this writer can read, by the ref the engine issued. The write was refused and receipted.",
        "IDENTITY_UNSETTLED": "The effect named a person through a mention that is not settled yet. Settle it with `self.identity.settle`, then act.",
        "BUDGET_SPENT": "The line a paid call spends on is spent, or the vault's budget policy refuses it. Use light or medium recall, or ask the owner to raise the line.",
        "MODEL_UNAVAILABLE": "The model the request needs did not answer usably; nothing stands in for it. Use light or medium recall, or ask the owner to check the model route.",
        "WRONG_ROOT": "The verb was named under the wrong root and nothing ran; the SDK never corrects and runs it. Issue a fresh call to the `replacement` the error carries.",
        "PENDING_ASK": "A verb hook asked before the verb ran: the verb waits on that open ask and was not refused. The error's `hook` names the invocation and the ask; a retry with the same invocation answers the same ask, never a second one. Each handle's `retry(pending, verb, input)` resends the call under it (UniFFI: the failure's `pending` payload); `oneiron mcp` resends an identical repeated tool call under the pending call's invocation.",
    }
    if set(codes) != remedies.keys():
        raise ValueError("Document remediation for each added/removed SDK error code")
    error_doc = "# Memory Wire typed errors\n\nEvery SDK failure carries `code`, `message`, and nonempty `suggestions`.\nUse the returned suggestions; do not parse message prose. No adapter swallows\nor downgrades the engine's refusal. Future remote codes pass through verbatim.\n\n| Code | Response |\n|---|---|\n"
    error_doc += "".join(f"| `{code}` | {remedies[code]} |\n" for code in codes)
    error_doc += "\nRemote server-specific codes and HTTP schemas are also indexed by\n[the engine API reference](../../oneiron.skills.md).\n"
    census = "# Memory Wire facade census\n\nThis is the complete **shipped SDK facade**, in manifest order. It is\nnot a claim that every engine-internal method is a public SDK verb.\n`scripts/sdk/agent-verbs.json` owns this list.\nNames are stable: a new export or rename must update the engine catalog,\nboth bindings and their export-census tests in one change.\n\n"
    census += "\n".join(f"- `{verb}`" for verb in verbs) + "\n"
    return {
        "docs/agent-sdk/quickstart.md": mirrored(readme, "packages/oneiron/README.md", "docs/agent-sdk/quickstart.md"),
        "docs/agent-sdk/types.md": "# Memory Wire type contract\n\n## JavaScript / TypeScript\n\n```ts\n" + ts + "```\n\n## Python\n\n```python\n" + py + "```\n",
        "docs/agent-sdk/errors.md": error_doc,
        "docs/agent-sdk/verbs.md": census,
        "llms.txt": "# Oneiron — Memory Wire\n\n> Actor-bound memory for agents. Start with vault.witness, vault.recall and vault.receipts.\n> The mirror below is full fidelity, generated from shipped SDK sources.\n\n## Memory Wire SDK\n\n- [Complete quickstarts and API](docs/agent-sdk/quickstart.md): JS/Python, embedded/remote, complete imports and typed errors.\n- [Type declarations](docs/agent-sdk/types.md): full TypeScript DTOs and Python stubs.\n- [Error catalogue](docs/agent-sdk/errors.md): stable codes, suggestions and remediation.\n- [Verb census](docs/agent-sdk/verbs.md): authoritative shipped facade and stable names.\n- [Vercel AI SDK tools](packages/oneiron-ai-sdk/README.md): thin three-verb satellite and runnable agent sample.\n- [LangGraph BaseStore](packages/oneiron-langgraph/README.md): exact actor-owned long-term keyed memory, not checkpoints.\n- [HTTP API](oneiron.skills.md): endpoint activation index, endpoint details and error schemas.\n",
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
