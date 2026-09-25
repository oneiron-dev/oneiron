# Test-only LSP process. Derives completions from opened Rust function names.
import json, re, sys
opened = {}
while True:
    header = sys.stdin.buffer.readline()
    if not header:
        break
    size = int(header.split(b":", 1)[1])
    assert sys.stdin.buffer.readline() == b"\r\n"
    msg = json.loads(sys.stdin.buffer.read(size))
    method = msg.get("method")
    params = msg.get("params", {})
    if method == "textDocument/didOpen":
        doc = params["textDocument"]
        opened[doc["uri"]] = doc["text"]
    if method == "textDocument/didClose":
        opened.pop(params["textDocument"]["uri"], None)
    if "id" not in msg:
        continue
    if method == "initialize":
        result = {"capabilities": {"completionProvider": {}, "diagnosticProvider": {"interFileDependencies": False, "workspaceDiagnostics": False}}}
    else:
        text = opened[params["textDocument"]["uri"]]
        if method == "textDocument/completion":
            result = [{"label": name} for name in re.findall(r"fn\s+(\w+)", text)]
        else:
            result = {"kind":"full", "items": [] if text.count("{") == text.count("}") else [{"code":"brace-mismatch"}]}
    body = json.dumps({"jsonrpc":"2.0", "id":msg["id"], "result":result}).encode()
    sys.stdout.buffer.write(b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    sys.stdout.buffer.flush()
