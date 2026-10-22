"""Tool calls for the house EXL3 server (FIX 8328): the request's tool specs
reach the chat template, a tool call the model writes comes back as
OpenAI `tool_calls`, and a replayed tool round renders.

The pinned Qwen template writes a call inside `<tool_call>` ... `</tool_call>`,
either as one JSON object (`{"name": ..., "arguments": {...}}`) or as
`<function=NAME>` with one `<parameter=KEY>` block per argument. It renders
a history call's arguments with `arguments|items`, an object, while the
OpenAI history the engine sends carries them as a JSON string:
`normalize_history` parses that string back into its object first.

A reply is read for tool calls only when its request named tools. A reply
whose blocks do not all parse keeps its text exactly as it came, with no
`tool_calls`; one that names no tool call is untouched.
"""
import json
import uuid

CALL_OPEN = "<tool_call>"
CALL_CLOSE = "</tool_call>"
FUNCTION_OPEN = "<function="
FUNCTION_CLOSE = "</function>"
PARAMETER_OPEN = "<parameter="
PARAMETER_CLOSE = "</parameter>"


def normalize_history(messages):
    """`messages` with each assistant tool call's string arguments parsed
    into the object the template iterates. A string that is not a JSON
    object is left as it came, and the template decides. The list given is
    not changed."""
    out = []
    for message in messages:
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        if not isinstance(calls, list) or not calls:
            out.append(message)
            continue
        fixed = []
        for call in calls:
            function = call.get("function") if isinstance(call, dict) else None
            arguments = function.get("arguments") if isinstance(function, dict) else None
            if isinstance(arguments, str):
                try:
                    parsed = json.loads(arguments) if arguments.strip() else {}
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    call = dict(call)
                    call["function"] = dict(function, arguments=parsed)
            fixed.append(call)
        out.append(dict(message, tool_calls=fixed))
    return out


def tool_specs(body):
    """The request's tool specs, as the template takes them: a list, empty
    when the request names none."""
    tools = body.get("tools")
    if tools is None:
        return []
    if not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
        raise ValueError("tools must be a list of objects")
    return tools


def _parameter_types(tools):
    """Each tool's parameter types, by tool name then parameter name."""
    types = {}
    for tool in tools:
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = function.get("name")
        parameters = function.get("parameters")
        properties = parameters.get("properties") if isinstance(parameters, dict) else None
        if isinstance(name, str):
            types[name] = properties if isinstance(properties, dict) else {}
    return types


def _is_string_type(schema):
    kind = schema.get("type") if isinstance(schema, dict) else None
    if isinstance(kind, list):
        return "string" in kind
    return kind == "string"


def _parameter_value(raw, schema):
    """One `<parameter>` block's value: as written for a string parameter,
    else its JSON value when it reads as one, else the text."""
    if raw.startswith("\n"):
        raw = raw[1:]
    if raw.endswith("\n"):
        raw = raw[:-1]
    if _is_string_type(schema):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _xml_call(inner, types):
    """A `<function=NAME>` call's name and arguments, or None."""
    start = inner.find(FUNCTION_OPEN)
    if start < 0 or inner[:start].strip():
        return None
    head_end = inner.find(">", start)
    if head_end < 0:
        return None
    name = inner[start + len(FUNCTION_OPEN):head_end].strip()
    if not name:
        return None
    rest = inner[head_end + 1:]
    close = rest.find(FUNCTION_CLOSE)
    if close >= 0:
        if rest[close + len(FUNCTION_CLOSE):].strip():
            return None
        rest = rest[:close]
    schemas = types.get(name, {})
    arguments = {}
    while True:
        rest = rest.lstrip()
        if not rest:
            break
        if not rest.startswith(PARAMETER_OPEN):
            return None
        key_end = rest.find(">")
        if key_end < 0:
            return None
        key = rest[len(PARAMETER_OPEN):key_end].strip()
        value_end = rest.find(PARAMETER_CLOSE, key_end + 1)
        if not key or value_end < 0:
            return None
        arguments[key] = _parameter_value(rest[key_end + 1:value_end], schemas.get(key))
        rest = rest[value_end + len(PARAMETER_CLOSE):]
    return name, arguments


def _json_call(inner):
    """A JSON `{"name": ..., "arguments": ...}` call's name and arguments,
    or None."""
    try:
        call = json.loads(inner)
    except ValueError:
        return None
    if not isinstance(call, dict) or not isinstance(call.get("name"), str) or not call["name"]:
        return None
    arguments = call.get("arguments", call.get("parameters", {}))
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except ValueError:
            return None
    if not isinstance(arguments, dict):
        return None
    return call["name"], arguments


def _call(inner, types):
    inner = inner.strip()
    if inner.startswith("{"):
        return _json_call(inner)
    return _xml_call(inner, types)


def parse(text, tools):
    """`text` read for tool calls: `(content, calls)`. With no tools, no
    marker, or a block that does not parse, `(text, [])` exactly. Otherwise
    the content is the text outside the blocks, stripped, and each call is an
    OpenAI tool call with a fresh id and its arguments as a JSON string. A
    last block the model ended without its close still counts when it
    parses."""
    if not tools or CALL_OPEN not in text:
        return text, []
    types = _parameter_types(tools)
    outside = []
    calls = []
    rest = text
    while True:
        start = rest.find(CALL_OPEN)
        if start < 0:
            outside.append(rest)
            break
        outside.append(rest[:start])
        rest = rest[start + len(CALL_OPEN):]
        end = rest.find(CALL_CLOSE)
        inner = rest if end < 0 else rest[:end]
        parsed = _call(inner, types)
        if parsed is None:
            return text, []
        name, arguments = parsed
        calls.append({
            "id": "call_" + uuid.uuid4().hex[:24],
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)},
        })
        if end < 0:
            break
        rest = rest[end + len(CALL_CLOSE):]
    return "".join(outside).strip(), calls


def answer_message(reasoning, content, tools, finish):
    """A buffered reply's message and finish reason, from its reasoning and
    content pieces: the answer read for tool calls when the request named
    tools and the answer ended on its own (a reply its cap cut keeps its
    text), else the text as it came."""
    text = "".join(content)
    calls = []
    if finish == "stop":
        text, calls = parse(text, tools)
    message = {"role": "assistant", "content": text}
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    if calls:
        message["tool_calls"] = calls
        finish = "tool_calls"
    return message, finish


def stream_deltas(calls):
    """A stream's `tool_calls` delta for `calls`, each with its index."""
    return [dict(call, index=index) for index, call in enumerate(calls)]


class StreamSplitter:
    """A streamed answer's text, held from the first `<tool_call>` on.

    `feed` returns the text that may go out now: everything before a marker,
    less a tail that could still begin one. `finish` reads what it held:
    `(tail, calls)`, the calls when every block parses, else the held text
    as it came, to go out as content."""

    def __init__(self, tools):
        self.tools = tools
        self.held = ""
        self.marked = False

    def feed(self, piece):
        if self.marked:
            self.held += piece
            return ""
        text = self.held + piece
        start = text.find(CALL_OPEN)
        if start >= 0:
            self.marked = True
            self.held = text[start:]
            return text[:start]
        keep = 0
        for size in range(min(len(CALL_OPEN) - 1, len(text)), 0, -1):
            if CALL_OPEN.startswith(text[-size:]):
                keep = size
                break
        self.held = text[len(text) - keep:] if keep else ""
        return text[:len(text) - keep] if keep else text

    def finish(self, read_calls=True):
        """The held text and the calls in it; with `read_calls` False (a
        reply cut short by its cap), the held text as content alone."""
        held, self.held = self.held, ""
        if not self.marked or not read_calls:
            return held, []
        content, calls = parse(held, self.tools)
        if not calls:
            return held, []
        return content, calls
