#!/usr/bin/env python3
"""Generate/check the Memory Wire agent mirror from the shipped SDK contract.

The mirror has two parts (untangle slice 4.3, D4 = a):
- committed: quickstart.md, errors.md and the root llms.txt, made from authored text. `--check` checks them.
- generated: types.md, facade-types.md and verbs.md, made from the verb table and the generated SDK outputs.
  They are not in git. CI publishes them at PUBLISHED (`--site`), and every build keeps a local copy
  (the SDK generator's `--out-dir`, crates/oneiron-sdk-generator, writes the same text itself; see README.md,
  "Building from source"). `generated_artifacts` below and the generator's `generate/docs.rs` must agree.
"""
from pathlib import Path
import argparse
import os
import re
import json

ROOT = Path(__file__).resolve().parents[3]
# Where CI's docs job publishes the mirror (.github/workflows/agent-sdk-docs.yml).
PUBLISHED = "https://oneiron-dev.github.io/oneiron/"
REPOSITORY = "https://github.com/oneiron-dev/oneiron/blob/main/"
GENERATED = ("docs/agent-sdk/types.md", "docs/agent-sdk/facade-types.md", "docs/agent-sdk/verbs.md")

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

def site_links(markdown, source):
    """Rewrites each relative link of `source` for the published site: a mirror file stays relative,
    anything else in the repository becomes its GitHub URL."""
    def relink(match):
        link = match.group(1)
        if re.match(r"[a-z][a-z0-9+.-]*:|#|/", link):
            return match.group(0)
        path, anchor = (link.split("#", 1) + [""])[:2]
        target = os.path.normpath(os.path.join(os.path.dirname(source), path))
        if target.startswith("docs/agent-sdk/") or target == "llms.txt":
            moved = os.path.relpath(target.removeprefix("docs/"), os.path.dirname(source.removeprefix("docs/")) or ".")
        else:
            moved = REPOSITORY + target
        return "](" + moved + ("#" + anchor if anchor else "") + ")"
    return re.sub(r"\]\(([^)\s]+)\)", relink, markdown)

def generated_artifacts(src):
    """The mirror files made from the verb table and the generated SDK outputs, which `src` holds
    (the tree after the generator's `--package`, or an `oneiron-sdk-generator --out-dir` directory)."""
    ts = (ROOT / "packages/oneiron/src/types.ts").read_text()
    py = (ROOT / "crates/oneiron-py/python/oneiron/__init__.pyi").read_text()
    py += (src / "crates/oneiron-py/python/oneiron/_facade_verbs.pyi").read_text()
    facade_ts = (src / "packages/oneiron/src/facade-types.ts").read_text()
    rows = [json.loads(path.read_text()) for path in sorted((ROOT / "scripts/sdk/verbs").glob("*.json"))]
    verbs = [row["name"] for row in rows if row.get("context", "memory") == "memory"]
    census = "# Memory Wire facade census\n\nThis is the complete **shipped SDK facade**, in verb-name order. It is\nnot a claim that every engine-internal method is a public SDK verb.\n`scripts/sdk/verbs/` owns this list.\nNames are stable: a new export or rename must update the engine catalog,\nboth bindings and their export-census tests in one change.\n\n"
    census += "\n".join(f"- `{verb}`" for verb in verbs) + "\n"
    return {
        "docs/agent-sdk/types.md": "# Memory Wire type contract\n\n## JavaScript / TypeScript\n\n```ts\n" + ts + "```\n\n## Python\n\n```python\n" + py + "```\n",
        "docs/agent-sdk/facade-types.md": "# Memory Wire facade types\n\nThe Python stubs carry the same names in the generated `facade_types.pyi`.\n\n```ts\n" + facade_ts + "```\n",
        "docs/agent-sdk/verbs.md": census,
    }

def committed_artifacts():
    """The mirror files made from authored text: in git, and checked by `--check`."""
    readme = (ROOT / "packages/oneiron/README.md").read_text()
    errors =(ROOT / "crates/oneiron-contracts/src/memory/error.rs").read_text()
    codes = re.findall(r'pub const MEMORY_CODE_\w+: &str = "([A-Z_]+)";', errors)
    remedies = {
        "BAD_REQUEST": "Correct input fields, types and units. Timestamps are Unix seconds.",
        "NOT_FOUND": "Refresh the identifier and current read scope before retrying.",
        "FORBIDDEN": "Respect the gate or identity refusal. Review pending consent; do not widen scope or retry blindly.",
        "INVALID_STATE": "Read the current lifecycle head, then make a new decision. Do not replay a stale target.",
        "INTERNAL_SERVER_ERROR": "Check the server endpoint, network and health. Report reproducible SDK boundary failures.",
        "LEASE_REQUIRED": "Use light or medium recall, or present a budget lease.",
        "OFF_RECORD_SESSION_DOOR": "Use the owning off-record session handle. The canonical witness door is not that handle.",
        "OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE": "No record holds a room's consent to one caller managing its whole off-record stretch, on any host. Act as a member instead: status and witness, and save or export your own copy through the room's routes.",
        "OWNER_BINDING_REQUIRED": "An owner device must bind this human actor in the authority log. Scope changes do not grant ownership.",
        "AUTHORITY_CLOCK_CORRUPT": "The vault's authority clock floor is damaged, so no authority reading stands on it. The owner runs `vault.authority.clock.repair`, then retries.",
        "VAULT_LOCKED_SINGLE_WRITER": "Connect to the process that owns this vault. Do not remove lock files or open a second writer.",
        "INVENTED_REFERENCE": "Name only records this writer can read, by the ref the engine issued. The write was refused and receipted.",
        "HOST_ACTION_REQUIRES_SUPPORT_GRANT": "A hosted operator's root acts as nobody inside a customer's vault. Ask the customer for a support grant; the operator's admin commands need none.",
        "IDENTITY_UNSETTLED": "The effect named a person through a mention that is not settled yet. Settle it with `self.identity.settle`, then act.",
        "OWNER_CONFIRM_REQUIRED": "A one-way act runs only on the owner's confirm of its preview. Call `vault.owner_confirm.preview` with the verb and its input, show the owner what it takes, and pass its `confirm` back in the call. A state that changed since needs a new preview.",
        "BUDGET_SPENT": "The line a paid call spends on is spent, or the vault's budget policy refuses it. Use light or medium recall, or ask the owner to raise the line.",
        "MODEL_UNAVAILABLE": "The model the request needs did not answer usably; nothing stands in for it. Use light or medium recall, or ask the owner to check the model route.",
        "MODEL_PIN_UNAVAILABLE": "The owner pinned a model that no offered seat serves; nothing stands in for it. Offer a seat for that model, or ask the owner to change or clear the pin.",
        "WRONG_ROOT": "The verb was named under the wrong root and nothing ran; the SDK never corrects and runs it. Issue a fresh call to the `replacement` the error carries.",
        "PENDING_ASK": "A verb hook asked before the verb ran: the verb waits on that open ask and was not refused. The error's `hook` names the invocation and the ask; a retry with the same invocation answers the same ask, never a second one. Each handle's `retry(pending, verb, input)` resends the call under it (UniFFI: the failure's `pending` payload); `oneiron mcp` resends an identical repeated tool call under the pending call's invocation.",
        "PACED_HOLD": "A count-bound budget window paced the call, and the engine holds it in its caller's fair line until its turn; nothing was refused. `resetsAt` names the earliest it runs and the message its deadline, after which it ends unrun. Send nothing again: a retry with the same invocation reads what the call came to. HTTP answers 202; over MCP the kind is `paced_hold` (-32020).",
        "WORLD_RECIPIENT_LIMIT": "The owner's read setting for a row's world keeps it from where this answer goes; the message names his choice, never the world. Read it where his choice admits, or ask him to change that setting. The row is there: do not treat this as not found.",
        "WORLD_PLACEMENT_UNVERIFIABLE": "A row's world placement, the rows a result came from or the vault root cannot be verified now, so nothing was released. No change to the request helps; retry once the vault has settled it.",
        "SANDBOX_PROPOSAL_DISK_FLOOR": "A foreign program's proposed file would cross the host disk's free-space floor, so the run failed and proposed nothing. The message names the bytes needed and free. No change to the request helps; run again once the host has room.",
    }
    if set(codes) != remedies.keys():
        raise ValueError("Document remediation for each added/removed SDK error code")
    # Codes a server door refuses with, defined outside the contracts crate
    # (FIX 5325, 6547, 8242): each read from its own source, so the table
    # names only codes that exist, never a copy.
    server_sources = [
        ("crates/oneiron-server/src/error/mod.rs", r'Self::DeadlineExceeded => "([A-Z_]+)",'),
        ("crates/oneiron/src/workspace_roster/rooms/audience_doors.rs", r'pub const MEMORY_CODE_\w+: &str = "([A-Z_]+)";'),
        ("crates/oneiron-vault-contract/src/lib/ctl.rs", r'Self::WritesFrozen => "([a-z_]+)",'),
        ("crates/oneiron-server/src/slide_render.rs", r'pub\(crate\) const RENDER_\w+: &str = "([a-z_]+)";'),
    ]
    server_codes = [code for path, pattern in server_sources for code in re.findall(pattern, (ROOT / path).read_text())]
    server_remedies = {
        "DEADLINE_EXCEEDED": "The caller's signals_deadline_ms expired. HTTP answers 408 and publishes no partial signal page or advanced cursor. Retry from the previous successful cursor with a larger budget, or omit the explicit deadline.",
        "AGENT_THREAD_WALK_IN_FORBIDDEN": "An agent may request to join a private thread it is not in; it cannot add itself. Ask the thread's members to add the agent, or have it request to join. HTTP answers 409; over MCP the kind is `agent_thread_walk_in_forbidden` (-32020).",
        "writes_frozen": "This hosted vault is paused while the service prepares to reap it; the pause names no duration. Retry once the reap is aborted or the vault wakes. HTTP answers 503; over MCP the kind is `writes_frozen` (-32020).",
        "render_deadline": "The deck render did not finish within its deadline, and nothing of it was kept. Ask again once `retry_after` seconds have passed. HTTP answers 503; over MCP the kind is `render_deadline` (-32020).",
        "render_memory_floor": "This machine cannot hold the deck render's memory past its reserve. Ask on a host with more memory. HTTP answers 503; over MCP the kind is `render_memory_floor` (-32020).",
        "render_disk_floor": "The vault's disk is at its free-space reserve, where the deck render writes its scratch. Ask again once `retry_after` seconds have passed and the disk has room. HTTP answers 503; over MCP the kind is `render_disk_floor` (-32020).",
    }
    if set(server_codes) != server_remedies.keys():
        raise ValueError("Document remediation for each added/removed server refusal code")
    error_doc = "# Memory Wire typed errors\n\nEvery SDK failure carries `code`, `message`, and nonempty `suggestions`.\nA refusal whose producer named stable reason codes also carries them, in that\nproducer's order (FIX 7398): `reasonCodes` on a JS `MemoryError` and in an HTTP\nerror body, `reason_codes` on a Python `MemoryError` and in an MCP error's\n`data.reason_codes`. Read them there, never out of `message`.\nUse the returned suggestions; do not parse message prose. No adapter swallows\nor downgrades the engine's refusal. Future remote codes pass through verbatim.\n\n| Code | Response |\n|---|---|\n"
    error_doc += "".join(f"| `{code}` | {remedies[code]} |\n" for code in codes)
    error_doc += "\n## Server refusal codes\n\nA server door refuses with these too; they pass through verbatim.\n\n| Code | Response |\n|---|---|\n"
    error_doc += "".join(f"| `{code}` | {server_remedies[code]} |\n" for code in server_codes)
    error_doc += "\nRemote server-specific codes and HTTP schemas are also indexed by\n[the engine API reference](../../oneiron.skills.md).\n"
    return {
        "docs/agent-sdk/quickstart.md": mirrored(readme, "packages/oneiron/README.md", "docs/agent-sdk/quickstart.md"),
        "docs/agent-sdk/errors.md": error_doc,
        "llms.txt": (ROOT / "scripts/sdk/llms.txt.in").read_text(),
    }

def write(files, out):
    for name, contents in files.items():
        path = out / name
        if path.exists() and path.read_text() == contents:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="check the committed mirror files; write nothing")
    parser.add_argument("--generated", action="store_true", help="also write the generated mirror files in the tree (not in git)")
    parser.add_argument("--from", dest="src", type=Path, default=ROOT, help="where the generated SDK outputs are (default: the tree)")
    parser.add_argument("--out", type=Path, help="write only the generated mirror files, under this directory")
    parser.add_argument("--site", type=Path, help="write the published site (every mirror file and llms.txt) under this directory")
    args = parser.parse_args()
    if args.site is not None:
        files = {**committed_artifacts(), **generated_artifacts(args.src)}
        write({name.removeprefix("docs/"): site_links(contents, name) for name, contents in files.items()}, args.site)
    elif args.out is not None:
        write(generated_artifacts(args.src), args.out)
    elif args.check:
        stale = [name for name, contents in committed_artifacts().items()
                 if not (ROOT / name).exists() or (ROOT / name).read_text() != contents]
        if stale:
            raise SystemExit("SDK-MIRROR-STALE: " + ", ".join(stale))
    else:
        write(committed_artifacts(), ROOT)
        if args.generated:
            write(generated_artifacts(args.src), ROOT)
