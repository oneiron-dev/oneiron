#!/usr/bin/env python3
"""FIX 8307 live probe: may a house offer declare reasoning_content_history?

Linux only; no server start, build, or model load. An ops evidence tool, not a
repository test (README.md, "Reasoning history probe").

Run once per offer against its already-running loopback house server. Both plain
and SSE three-turn conversations must pass. The script does not exercise the
Rust adapter; the lead must also check the implemented offer-to-wire path.
Runtime/weights revision labels are operator assertions; pair the JSON with the
fleet log and service recipe.

A house llama.cpp launch advertises and answers as its FIX 7895 launch alias,
`oneiron-llama/<32 hex>/<64 hex>`, not the configured wire id. On the llama
backend that alias stands for --wire-id; the raw ids are kept in the evidence.

On llama the run is bound to the launch that answered it (FIX 8417): the one
alias its replies named leads to the same-origin `/<digest>.json` launch
manifest, which must hash to that digest and name schema 1, the llama_cpp
backend, the alias's epoch and --wire-id. The --template file must then be
the template that launch selected for these requests, which all offer a tool:
the manifest's `templates.tool_use` entry when it lists one, else
`templates.default`, matched by its own SHA-256, never the aggregate
`identity.template`. The selection counts as known only when the manifest
names the GGUF's own templates (`identity.template`) and the server's /props
shows the same templates; anything else stays unverified, and the run is not
a pass.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

# FIX 7895: the one alias a house llama.cpp launch serves under, read as the
# engine reads it (oneiron::llm::parse_llama_alias): exactly this prefix, 32
# lowercase hex digits, a slash, 64 lowercase hex digits, nothing else.
LLAMA_ALIAS = re.compile(r"oneiron-llama/[0-9a-f]{32}/[0-9a-f]{64}")


def digest(path):
    path = Path(path).resolve(strict=True)
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return {"path": str(path), "sha256": value.hexdigest()}


def check(evidence, name, condition):
    evidence["checks"].append({"name": name, "passed": bool(condition)})
    if not condition:
        raise ValueError(name)


def served(args, evidence, served_id):
    """Whether a /v1/models id or reply model stands for --wire-id.

    It is --wire-id itself, or, on the llama backend, a launch alias. Every id
    is recorded raw. One run is one launch: a second alias means the server
    restarted mid-run, and the run fails rather than mix two launches.
    """
    ids = evidence["served_model_ids"]
    if served_id not in ids:
        ids.append(served_id)
    if served_id == args.wire_id:
        return True
    if (args.backend != "llama" or not isinstance(served_id, str)
            or LLAMA_ALIAS.fullmatch(served_id) is None):
        return False
    if evidence["llama_alias"] is None:
        evidence["llama_alias"] = served_id
    return evidence["llama_alias"] == served_id


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def decode_sse(raw):
    message = {"role": "assistant", "content": ""}
    calls = {}
    finish = None
    done = False
    models = set()
    for block in raw.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip(" ") for line in block.splitlines()
                         if line.startswith("data:"))
        if not data:
            continue
        if data == "[DONE]":
            done = True
            break
        event = json.loads(data)
        if "error" in event:
            raise ValueError(f"SSE error: {event['error']}")
        if event.get("model"):
            models.add(event["model"])
        choices = event.get("choices", [])
        if not choices:
            continue
        if len(choices) != 1 or choices[0].get("index", 0) != 0:
            raise ValueError("expected one SSE choice at index zero")
        choice = choices[0]
        delta = choice.get("delta", {})
        if delta.get("role", "assistant") != "assistant":
            raise ValueError("unexpected SSE role")
        for field in ("content", "reasoning_content"):
            if delta.get(field) is not None:
                if not isinstance(delta[field], str):
                    raise ValueError(f"non-string SSE {field}")
                message[field] = message.get(field, "") + delta[field]
        for fragment in delta.get("tool_calls", []):
            index = fragment["index"]
            call = calls.setdefault(index, {"id": "", "type": "function",
                                           "function": {"name": "", "arguments": ""}})
            if fragment.get("type", "function") != "function":
                raise ValueError("non-function SSE tool call")
            # Match the adapter: repeated full ids/names are not concatenated.
            if fragment.get("id") and call["id"] != fragment["id"]:
                call["id"] += fragment["id"]
            function = fragment.get("function", {})
            if function.get("name") and call["function"]["name"] != function["name"]:
                call["function"]["name"] += function["name"]
            call["function"]["arguments"] += function.get("arguments", "")
        if choice.get("finish_reason") is not None:
            if finish is not None and finish != choice["finish_reason"]:
                raise ValueError("conflicting SSE finish reasons")
            finish = choice["finish_reason"]
    if not done or finish is None:
        raise ValueError("SSE ended without both finish_reason and [DONE]")
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    return message, finish, sorted(models)


class Client:
    def __init__(self, args, evidence):
        base = urlsplit(args.base_url)
        if (base.scheme != "http" or base.hostname not in ("127.0.0.1", "localhost", "::1")
                or base.path not in ("", "/", "/v1", "/v1/")
                or base.username or base.password or base.query or base.fragment):
            raise ValueError("run on the GPU host; base-url must be a loopback HTTP origin or /v1")
        self.base = args.base_url.rstrip("/")
        if self.base.endswith("/v1"):
            self.base = self.base[:-3]
        self.args = args
        self.evidence = evidence
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.headers = {"Content-Type": "application/json"}
        if args.api_key_env:
            self.headers["Authorization"] = "Bearer " + os.environ[args.api_key_env]

    def fetch(self, name, path):
        """One GET on the server's own origin, its raw bytes returned whole:
        no redirect is followed, and the evidence keeps their SHA-256."""
        record = {"name": name, "path": path, "request": None}
        self.evidence["exchanges"].append(record)
        request = Request(self.base + path, headers=self.headers, method="GET")
        try:
            with self.opener.open(request, timeout=self.args.timeout) as reply:
                record["status"] = reply.status
                raw = reply.read()
        except HTTPError as error:
            record["status"] = error.code
            raise ValueError(f"{name}: HTTP {error.code}") from error
        record["sha256"] = hashlib.sha256(raw).hexdigest()
        record["bytes"] = len(raw)
        return raw

    def exchange(self, name, path, body=None, streaming=False):
        record = {"name": name, "path": path, "request": copy.deepcopy(body)}
        self.evidence["exchanges"].append(record)
        request = Request(self.base + path,
                          data=None if body is None else json.dumps(body).encode("utf-8"),
                          headers=self.headers, method="GET" if body is None else "POST")
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=self.args.timeout) as reply:
                record["status"] = reply.status
                record["content_type"] = reply.headers.get("Content-Type", "")
                raw = reply.read().decode("utf-8")
        except HTTPError as error:
            record["status"] = error.code
            record["raw_response"] = error.read().decode("utf-8", errors="replace")
            raise ValueError(f"{name}: HTTP {error.code}") from error
        finally:
            record["elapsed_s"] = round(time.monotonic() - started, 3)
        record["raw_response"] = raw
        if not 200 <= record["status"] < 300:
            raise ValueError(f"{name}: HTTP {record['status']}")
        if streaming:
            if "text/event-stream" not in record["content_type"]:
                raise ValueError(f"{name}: expected SSE response")
            message, finish, models = decode_sse(raw)
        else:
            response = json.loads(raw)
            record["response"] = response
            if body is None:
                return response
            if "error" in response:
                raise ValueError(f"{name}: provider error")
            choices = response["choices"]
            if len(choices) != 1:
                raise ValueError(f"{name}: expected exactly one choice")
            message = choices[0]["message"]
            finish = choices[0].get("finish_reason")
            models = [response.get("model")]
        record["assistant"] = copy.deepcopy(message)
        record["finish_reason"] = finish
        record["response_models"] = models
        matches = [served(self.args, self.evidence, model) for model in models]
        check(self.evidence, name + ": wire model identity", bool(matches) and all(matches))
        check(self.evidence, name + ": assistant role", message.get("role") == "assistant")
        return message, finish


def reply_alias(evidence):
    """The one launch alias the run's actual replies named, or None when they
    named none or more than one."""
    aliases = {model for exchange in evidence["exchanges"]
               for model in exchange.get("response_models") or []
               if isinstance(model, str) and LLAMA_ALIAS.fullmatch(model)}
    return aliases.pop() if len(aliases) == 1 else None


def text_sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if isinstance(text, str) else None


def bind_launch(client, args, evidence):
    """FIX 8417: binds a llama run to the launch that answered it, and its
    --template file to the template that launch selected for the run's tool
    requests. Each step is a named check; ambiguity is never a match."""
    binding = {"alias": None, "manifest_verified": False, "template_selected": None,
               "template_binding": "unverified"}
    evidence["launch_binding"] = binding
    alias = reply_alias(evidence)
    check(evidence, "launch binding: the replies named one launch alias", alias is not None)
    binding["alias"] = alias
    _, epoch, digest = alias.split("/")
    raw = client.fetch("launch manifest", "/" + digest + ".json")
    check(evidence, "launch binding: manifest bytes hash to the alias digest",
          hashlib.sha256(raw).hexdigest() == digest)
    manifest = json.loads(raw)
    check(evidence, "launch binding: manifest schema 1", manifest.get("schema_version") == 1)
    check(evidence, "launch binding: llama_cpp backend", manifest.get("backend") == "llama_cpp")
    check(evidence, "launch binding: manifest epoch is the alias epoch",
          manifest.get("backend_epoch") == epoch)
    check(evidence, "launch binding: manifest wire id is --wire-id",
          manifest.get("configured_wire_id") == args.wire_id)
    binding["manifest_verified"] = True
    templates = manifest.get("templates") or {}
    default, tool_use = templates.get("default"), templates.get("tool_use")
    # Every request offers a tool, so the launch renders its tool-use
    # template when the GGUF has one, else its default. The selection is
    # known only when the manifest names the GGUF's own templates and /props
    # shows the same ones.
    selected_name, selected = ("tool_use", tool_use) if tool_use else ("default", default)
    props = client.exchange("props", "/props")
    known = ("template" in (manifest.get("identity") or {})
             and isinstance(selected, dict) and isinstance(default, dict)
             and text_sha256(props.get("chat_template")) == default.get("sha256")
             and (tool_use is None
                  or text_sha256(props.get("chat_template_tool_use")) == tool_use.get("sha256")))
    binding["template_selected"] = selected_name if known else None
    check(evidence, "launch binding: the launch's template selection is known", known)
    matched = evidence["files"]["template"]["sha256"] == selected.get("sha256")
    binding["template_binding"] = "verified" if matched else "mismatch"
    check(evidence, "launch binding: --template is the selected " + selected_name + " template", matched)


def history(message):
    # No reasoning-to-content merge, id replacement, XML parsing, or argument
    # conversion. Send back the native history fields exactly as returned.
    return copy.deepcopy({key: message[key] for key in
                          ("role", "content", "reasoning_content", "tool_calls")
                          if key in message})


def roundtrip(client, args, evidence, streaming):
    mode = "stream" if streaming else "plain"
    key = "probe-" + secrets.token_hex(8)
    messages = [
        {"role": "system", "content":
         "This is a tool protocol probe. Think briefly. Call lookup_probe_value exactly once "
         "with the user's key; only that tool knows the value. Before calling, write a short "
         "public preamble in ordinary assistant content, separate from reasoning_content. "
         "After the tool result, output exactly RESULT=<value>, replacing <value> with the "
         "tool's value. No quotes, explanation, markdown, or further tool calls."},
        {"role": "user", "content": "Look up the value for key " + key + "."},
    ]
    tool = {"type": "function", "function": {
        "name": "lookup_probe_value", "description": "Returns the private value for this probe key.",
        "parameters": {"type": "object", "properties": {"key": {"type": "string"}},
                       "required": ["key"], "additionalProperties": False}}}
    controls = {"model": args.wire_id, "stream": streaming, "temperature": 0,
                "seed": 8307, "max_tokens": args.max_tokens,
                "reasoning_budget_tokens": args.reasoning_budget,
                "reasoning_effort": args.effort,
                "chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": args.effort}}
    if streaming:
        controls["stream_options"] = {"include_usage": True}
    if args.backend == "exl3":
        controls["oneiron_solo"] = True

    first = dict(controls, messages=messages, tools=[tool], tool_choice="auto")
    assistant, finish = client.exchange(mode + ".turn1", "/v1/chat/completions", first, streaming)
    check(evidence, mode + ": tool finish", finish == "tool_calls")
    for field in ("reasoning_content", "content"):
        check(evidence, mode + ": turn1 nonempty " + field,
              isinstance(assistant.get(field), str) and bool(assistant[field].strip()))
    calls = assistant.get("tool_calls")
    check(evidence, mode + ": exactly one tool call", isinstance(calls, list) and len(calls) == 1)
    call = calls[0]
    call_id = call.get("id")
    check(evidence, mode + ": nonempty tool id", isinstance(call_id, str) and bool(call_id.strip()))
    check(evidence, mode + ": function type", call.get("type") == "function")
    function = call["function"]
    check(evidence, mode + ": function name", function.get("name") == "lookup_probe_value")
    check(evidence, mode + ": JSON-string arguments", isinstance(function.get("arguments"), str))
    check(evidence, mode + ": arguments", json.loads(function["arguments"]) == {"key": key})

    # Minted only AFTER the tool call: no model can know this from the prompt.
    value = secrets.token_hex(16)
    expected = "RESULT=" + value
    returned = {"key": key, "value": value}
    tool_message = {"role": "tool", "tool_call_id": call_id,
                    "content": json.dumps(returned, separators=(",", ":"), ensure_ascii=False)}
    replayed = history(assistant)
    messages += [replayed, tool_message]
    check(evidence, mode + ": reasoning/content/tools replayed unchanged",
          all(replayed[field] == assistant[field] for field in
              ("reasoning_content", "content", "tool_calls")))
    check(evidence, mode + ": result id matches assistant id",
          tool_message["tool_call_id"] == replayed["tool_calls"][0]["id"])
    second = dict(controls, messages=messages, tools=[tool], tool_choice="auto")
    answer, finish = client.exchange(mode + ".turn2", "/v1/chat/completions", second, streaming)
    check(evidence, mode + ": turn2 clean answer", finish == "stop" and not answer.get("tool_calls"))
    check(evidence, mode + ": tool value used", answer.get("content", "").strip() == expected)
    check(evidence, mode + ": turn2 reasoning available for turn3",
          isinstance(answer.get("reasoning_content"), str) and bool(answer["reasoning_content"].strip()))
    messages += [history(answer), {"role": "user", "content":
                                  "Repeat the same RESULT line from the tool value. No tools."}]
    third = dict(controls, messages=messages, tools=[tool], tool_choice="auto")
    confirmation, finish = client.exchange(mode + ".turn3", "/v1/chat/completions", third, streaming)
    check(evidence, mode + ": turn3 clean answer", finish == "stop" and not confirmation.get("tool_calls"))
    check(evidence, mode + ": value survives third turn", confirmation.get("content", "").strip() == expected)
    evidence["conversations"].append({"mode": mode, "key": key, "call_id": call_id,
                                      "tool_result": returned, "expected": expected, "passed": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--backend", choices=("llama", "exl3"), required=True)
    parser.add_argument("--offer", required=True, help="exact engine provider/model@revision")
    parser.add_argument("--wire-id", default="qwen3.8-27b",
                        help="the offer's configured wire model id, sent as the request model; "
                             "on the llama backend its launch alias stands for it")
    parser.add_argument("--server-revision", required=True)
    parser.add_argument("--weights-revision", required=True)
    parser.add_argument("--template", type=Path, required=True,
                        help="actual deployed chat template bytes; on llama, the template the launch selects "
                             "for tool requests (its tool-use template when it has one)")
    parser.add_argument("--runtime-file", type=Path, required=True, help="actual server binary or Python source")
    parser.add_argument("--tokenizer-file", type=Path, action="append", default=[])
    parser.add_argument("--booking-ref", required=True, help="fleet booking id or unique label paired with its log")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--api-key-env", help="optional env var name, value is never recorded")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--reasoning-budget", type=int, default=512)
    parser.add_argument("--effort", choices=("low", "medium", "xhigh"), default="medium")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("fleet Linux GPU host only; never run this probe on the owner's Mac")
    if args.max_tokens <= 0 or not 0 < args.reasoning_budget < args.max_tokens or args.timeout <= 0:
        parser.error("positive timeout and 0 < reasoning-budget < max-tokens required")
    evidence = {"schema": "fix-8307-house-roundtrip-v1", "started_unix": time.time(),
                "hostname": socket.gethostname(), "platform": platform.platform(),
                "python": platform.python_version(), "offer": args.offer, "wire_id": args.wire_id,
                "backend": args.backend, "base_url": args.base_url, "booking_ref": args.booking_ref,
                "server_revision_asserted": args.server_revision,
                "weights_revision_asserted": args.weights_revision,
                "required_modes": ["plain", "stream"], "conversations": [], "exchanges": [],
                "advertised_model_ids": None, "served_model_ids": [], "llama_alias": None,
                "checks": [], "declaration_ready": False,
                "scope": "direct server protocol, not Rust adapter execution"}
    # Exclusive create: a failed run and a later pass never overwrite one another.
    with args.evidence.resolve().open("x", encoding="utf-8") as output:
        try:
            evidence["files"] = {"probe": digest(__file__), "template": digest(args.template),
                                 "runtime": digest(args.runtime_file),
                                 "tokenizers": [digest(path) for path in args.tokenizer_file]}
            client = Client(args, evidence)
            models = client.exchange("models", "/v1/models")
            advertised = [row.get("id") for row in models.get("data", [])]
            evidence["advertised_model_ids"] = advertised
            check(evidence, "requested wire model is advertised",
                  any([served(args, evidence, model) for model in advertised]))
            for streaming in (False, True):
                roundtrip(client, args, evidence, streaming)
            if args.backend == "llama":
                bind_launch(client, args, evidence)
            evidence["declaration_ready"] = True
        except Exception as error:
            evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        finally:
            evidence["finished_unix"] = time.time()
            json.dump(evidence, output, indent=2, ensure_ascii=False)
            output.write("\n")
    print(json.dumps({"evidence": str(args.evidence.resolve()),
                      "declaration_ready": evidence["declaration_ready"]}))
    return 0 if evidence["declaration_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
