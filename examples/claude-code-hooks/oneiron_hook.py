#!/usr/bin/env python3
"""Claude Code hooks that let a session use your Oneiron vault.

session-start  (SessionStart)            recall a short block of context for the
                                          project and print it; Claude Code adds
                                          stdout to the session's context.
hand-over      (PreCompact, Stop,        queue the session's transcript for the
                SessionEnd)              running `oneiron serve` to import.

Every hook reads the event JSON Claude Code sends on stdin. A hook never blocks
Claude Code and never prints an error into the session: if the vault is down or
anything fails, it prints nothing and exits 0. It never reads a credential
itself; `oneiron mcp` reads the agent's credential file.

Python 3.9 or newer, standard library only. See docs/ops/claude-code-hooks.md.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import subprocess
import sys
import time

MAX_EVENT_BYTES = 1 << 20
ITEM_CHARS = 400
BLOCK_CHARS = 6000


def read_event() -> dict:
    raw = sys.stdin.buffer.read(MAX_EVENT_BYTES)
    event = json.loads(raw or b"{}")
    return event if isinstance(event, dict) else {}


# --- session-start ---------------------------------------------------------


def project_name(cwd: str) -> str:
    """The git repository's folder name, else the working directory's."""
    top = cwd
    try:
        found = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if found.returncode == 0 and found.stdout.strip():
            top = found.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return os.path.basename(os.path.normpath(top))


class Bridge:
    """One `oneiron mcp` process, spoken to one request at a time. It runs in
    its own process group, so giving up also ends the `curl` it started."""

    def __init__(self, command: list[str], deadline: float):
        self.deadline = deadline
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.buffer = b""

    def send(self, message: dict) -> None:
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        self.process.stdin.flush()

    def call(self, request_id: int, method: str, params: dict) -> dict:
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            line = self.read_line()
            try:
                answer = json.loads(line)
            except ValueError:
                continue
            if isinstance(answer, dict) and answer.get("id") == request_id:
                if "error" in answer:
                    raise RuntimeError(method)
                return answer.get("result") or {}

    def read_line(self) -> bytes:
        stdout = self.process.stdout
        while b"\n" not in self.buffer:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError
            ready, _, _ = select.select([stdout], [], [], left)
            if not ready:
                raise TimeoutError
            chunk = os.read(stdout.fileno(), 65536)
            if not chunk:
                raise EOFError
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line

    def close(self) -> None:
        try:
            self.process.stdin.close()
            self.process.wait(timeout=max(0.1, self.deadline - time.monotonic()))
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except OSError:
            pass
        self.process.wait()


def tool_call(tools: list, query: str, limit: int) -> tuple[str, dict]:
    """`recall` at the light effort (no model, no embedding) when the server
    lists it; otherwise the lexical `memory.query`."""
    by_name = {tool.get("name"): tool for tool in tools if isinstance(tool, dict)}
    name = "recall" if "recall" in by_name else "memory.query"
    tool = by_name.get(name)
    if tool is None:
        raise LookupError(name)
    schema = tool.get("inputSchema", {}).get("properties", {})
    version = schema.get("schema_version", {}).get("const", "mcp_tool_args.v1")
    if name == "recall":
        arguments = {"spec": {"query": query, "effort": "light", "limit": limit}}
    else:
        arguments = {
            "request": {"query": query, "limit": limit, "view": "summary", "countMode": "none"}
        }
    return name, {
        "schema_version": version,
        "consent": {
            "policy_ref": "policy:claude-code-hooks",
            "purpose": "recall context for a new Claude Code session",
        },
        "arguments": arguments,
    }


def hit_text(item: dict):
    """One hit's words: a recall pack item's `value_text`, after a claim's
    predicate; in a query result, a message's `body.content` or a claim's
    `body.pred` and `body.val`. A pack item for a record with no words carries
    its body as JSON (an actor's name, say); that gives none. A message's own
    words are kept even when they read as JSON."""
    text = item.get("value_text")
    if isinstance(text, str):
        if isinstance(item.get("predicate"), str):
            return f"{item['predicate']}: {text}"
        if item.get("kind") != "MESSAGE" and structural(text):
            return None
        return text
    body = item.get("body")
    if not isinstance(body, dict):
        return None
    if isinstance(body.get("content"), str):
        return body["content"]
    if isinstance(body.get("val"), (str, int, float)) and not isinstance(body.get("val"), bool):
        predicate = body.get("pred")
        value = str(body["val"])
        return f"{predicate}: {value}" if isinstance(predicate, str) else value
    return None


def texts(value, found: list) -> None:
    """Every hit's text, in order, from the result's `items` lists."""
    if isinstance(value, dict):
        items = value.get("items")
        if isinstance(items, list):
            for item in items:
                text = hit_text(item) if isinstance(item, dict) else None
                if text:
                    found.append(text)
            return
        for child in value.values():
            texts(child, found)
    elif isinstance(value, list):
        for child in value:
            texts(child, found)


def structural(text: str) -> bool:
    """A record's body as JSON, not words to show."""
    if not text.lstrip().startswith("{"):
        return False
    try:
        return isinstance(json.loads(text), dict)
    except ValueError:
        return False


def session_start(args: argparse.Namespace) -> None:
    event = read_event()
    cwd = event.get("cwd") or os.getcwd()
    query = args.query or project_name(cwd).replace("-", " ").replace("_", " ")
    if not query.strip():
        return
    command = [
        args.oneiron,
        "mcp",
        "--url",
        args.url,
        "--surface",
        "tool-first",
        "--credential-file",
        args.credential_file,
    ]
    bridge = Bridge(command, time.monotonic() + args.timeout)
    try:
        bridge.call(
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "oneiron-claude-code-hooks", "version": "1"},
            },
        )
        bridge.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = bridge.call(2, "tools/list", {})
        name, arguments = tool_call(listed.get("tools", []), query, args.limit)
        result = bridge.call(3, "tools/call", {"name": name, "arguments": arguments})
    finally:
        bridge.close()
    if result.get("isError"):
        return
    found: list = []
    texts(result.get("structuredContent"), found)
    if not found:
        for block in result.get("content") or []:
            try:
                texts(json.loads(block.get("text", "")), found)
            except (AttributeError, TypeError, ValueError):
                continue
    lines, seen, size = [], set(), 0
    for text in found:
        text = " ".join(text.split())
        if not text or text in seen:
            continue
        seen.add(text)
        if len(text) > ITEM_CHARS:
            text = text[: ITEM_CHARS - 1] + "…"
        if size + len(text) > BLOCK_CHARS or len(lines) >= args.limit:
            break
        lines.append(f"- {text}")
        size += len(text)
    if lines:
        print(f'From your Oneiron vault, for "{query}" (recalled at session start; may be dated):')
        print("\n".join(lines))


# --- hand-over -------------------------------------------------------------


def hand_over(args: argparse.Namespace) -> None:
    transcript = read_event().get("transcript_path")
    if not isinstance(transcript, str) or not transcript:
        return
    command = [args.oneiron, "import", "claude-code", transcript, "--queue"]
    if args.config:
        command += ["--config", args.config]
    subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=args.timeout,
    )


class Parser(argparse.ArgumentParser):
    """A mistyped hook command is reported and never blocks: exit 2 would
    stop a compaction or keep a turn from ending, so a usage error exits 1,
    which Claude Code shows as a hook error and goes on."""

    def error(self, message: str) -> None:
        sys.stderr.write(f"oneiron_hook.py: {message}\n")
        sys.exit(1)


def main() -> None:
    common = Parser(add_help=False)
    common.add_argument("--oneiron", default="oneiron", help="the oneiron binary")
    common.add_argument("--timeout", type=float, default=8.0, help="seconds before giving up")
    parser = Parser(description=__doc__.splitlines()[0])
    events = parser.add_subparsers(dest="event", required=True)
    start = events.add_parser("session-start", parents=[common])
    start.add_argument("--url", required=True, help="the running server's origin")
    start.add_argument(
        "--credential-file", required=True, help="the agent credential `token agent --out` wrote"
    )
    start.add_argument("--limit", type=int, default=8, help="most hits printed")
    start.add_argument("--query", help="recall this instead of the project's name")
    over = events.add_parser("hand-over", parents=[common])
    over.add_argument("--config", help="the serve config, for where the import queue is")
    args = parser.parse_args()
    try:
        if args.event == "session-start":
            session_start(args)
        else:
            hand_over(args)
    except Exception:  # A down vault or a slow one never breaks the session.
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
