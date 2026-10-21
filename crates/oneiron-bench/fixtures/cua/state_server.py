#!/usr/bin/env python3
"""Two-listener, in-memory CUA fixture server. No outbound operations exist."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
# Explicit sibling loading works with python3 -I (which omits the script directory).
_spec = importlib.util.spec_from_file_location("cua_gen_data", ROOT / "gen_data.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)
MAX_BODY = 131072
DRAFT_FIELDS = ("to", "subject", "body", "link", "scheduled_time")
FORM_FIELDS = ("sector", "amount_band", "company_name", "website", "what_you_do")


class RequestError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def require(condition, message, status=400):
    if not condition:
        raise RequestError(status, message)


def text(payload, field):
    value = payload.get(field)
    require(isinstance(value, str), f"{field} must be a string")
    return value


class FixtureApp:
    def __init__(self, event_log, token, external_data_dir=None):
        if len(token) < 32 or token.strip() != token:
            raise ValueError("supply a random bearer token of at least 32 characters")
        self.token = token
        self.event_log = Path(event_log)
        self.external_data_dir = external_data_dir
        self.lock = threading.RLock()
        self.runs = {}
        self.sequence = 0
        # Fail before binding either listener if the log is not writable.
        with self.event_log.open("a", encoding="utf-8"):
            pass

    def log(self, event):
        self.sequence += 1
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "sequence": self.sequence, **event}
        with self.event_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()

    def reset(self, payload):
        fixture, version, seed = payload.get("fixture"), payload.get("version"), payload.get("seed")
        require(fixture in gen.FIXTURES and version in gen.VERSIONS, "unknown fixture or version")
        require(type(seed) is int, "seed must be an integer")
        data = gen.make_data(seed, self.external_data_dir)[fixture]
        pages = gen.render_pages(fixture, version, data)
        state = {"fixture":fixture, "version":version, "seed":seed, "run_id":secrets.token_hex(16), "presses":[], "send_count":0, "submit_count":0, "wrong_target_count":0, "consent_dismissed":version != "v3"}
        if fixture == "F2":
            state["fields"] = {field:"" for field in FORM_FIELDS}
            state["field_saves"] = []
        if fixture == "F3":
            state["drafts"] = {row["id"]:{**{field:"" for field in DRAFT_FIELDS}, "saved":False} for row in data["recipients"]}
        if fixture == "F4":
            state.update({"note":"", "send_enabled":False, "opened_on":None, "viewed_profile":None, "dialog_open":False, "search_query":""})
        if fixture == "F5":
            state.update({"cells":copy.deepcopy(data["cells"]), "computed":gen.totals(data["cells"]), "cell_saves":[]})
        run = {"state":state, "data":data, "pages":pages, "expected":gen.expected(fixture,data), "data_sha256":hashlib.sha256(gen.dump(data).encode()).hexdigest()}
        self.log({"channel":"private", "action":"reset", "fixture":fixture, "version":version, "seed":seed, "run_id":state["run_id"]})
        self.runs[fixture] = run
        return {"fixture":fixture, "version":version, "seed":seed, "run_id":state["run_id"], "entry":f"/{fixture}/{version}/index.html", "data_sha256":run["data_sha256"]}

    def private(self, method, path, payload=None, bearer=""):
        with self.lock:
            if not hmac.compare_digest(bearer.encode(), self.token.encode()):
                return 401, {"error":"unauthorized"}
            try:
                if method == "GET" and path == "/health":
                    return 200, {"ok":True, "fixtures":sorted(self.runs)}
                if method == "POST" and path == "/reset":
                    require(isinstance(payload,dict), "JSON object required")
                    return 200, self.reset(payload)
                if method == "GET" and path.startswith("/state/"):
                    fixture = path[len("/state/"):]
                    require(fixture in self.runs, "fixture not reset", 404)
                    run = self.runs[fixture]
                    return 200, copy.deepcopy(run["state"] | {"expected":run["expected"], "data_sha256":run["data_sha256"]})
                raise RequestError(404, "not found")
            except (ValueError, KeyError, TypeError) as error:
                return 400, {"error":str(error)}
            except RequestError as error:
                return error.status, {"error":str(error)}

    def static(self, path):
        with self.lock:
            if path in ("/assets/app.js", "/assets/style.css"):
                file = ROOT / path.lstrip("/")
                return 200, "text/javascript; charset=utf-8" if file.suffix == ".js" else "text/css; charset=utf-8", file.read_bytes()
            parts = path.strip("/").split("/")
            if len(parts) < 2 or parts[0] not in gen.FIXTURES or parts[1] not in gen.VERSIONS:
                return 404, "text/plain", b"Not found\n"
            fixture, version = parts[:2]
            run = self.runs.get(fixture)
            if run is None or run["state"]["version"] != version:
                return 409, "text/plain", b"Fixture/version not reset\n"
            relative = "/".join(parts[2:]) or "index.html"
            if relative not in run["pages"]:
                return 404, "text/plain", b"Not found\n"
            return 200, "text/html; charset=utf-8", run["pages"][relative].encode()

    def public(self, method, path, payload=None, run_id="", parse_error=None):
        """Only the page API. Called by HTTP and by the direct handler check."""
        with self.lock:
            status, response, effect = 200, {}, "read"
            parts = path.strip("/").split("/")
            fixture = parts[0] if parts else ""
            active = self.runs.get(fixture)
            candidate = None
            try:
                require(parse_error is None, parse_error or "malformed JSON")
                require(len(parts) == 4 and parts[2] == "api", "not found", 404)
                fixture, version, _, action = parts
                require(fixture in gen.FIXTURES and version in gen.VERSIONS, "not found", 404)
                require(active is not None and active["state"]["version"] == version, "fixture/version not reset", 409)
                if method == "GET" and action == "data":
                    state = active["state"]
                    view_keys = {"F1":(), "F2":("fields",), "F3":("drafts",), "F4":("note","opened_on","send_enabled","dialog_open"), "F5":("cells","computed")}[fixture]
                    response = {"run_id":state["run_id"], "consent_dismissed":state["consent_dismissed"], "source":{} if fixture == "F1" else active["data"], "view":{key:state[key] for key in view_keys}}
                else:
                    require(method == "POST", "method not allowed", 405)
                    require(run_id == active["state"]["run_id"], "stale or missing run id", 409)
                    require(isinstance(payload,dict), "JSON object required")
                    candidate = copy.deepcopy(active["state"])
                    require(candidate["consent_dismissed"] or action == "consent", "consent overlay is active", 409)
                    effect = self.mutate(fixture, action, payload, candidate, active["data"])
                    response = {"ok":True, "effect":effect}
            except RequestError as error:
                status, response, effect = error.status, {"error":str(error)}, "rejected"
                candidate = None
            self.log({"channel":"public", "method":method, "path":path, "payload":payload, "run_id":active["state"]["run_id"] if active else None, "request_run_id":run_id, "status":status, "effect":effect})
            if candidate is not None:
                active["state"] = candidate
            return status, copy.deepcopy(response)

    def mutate(self, fixture, action, payload, state, data):
        def press(control, **extra):
            state["presses"].append({"control":control, **extra})
        if action == "consent":
            require(state["version"] == "v3", "no consent banner")
            state["consent_dismissed"] = True
            press("dismiss-consent")
            return "consent-dismissed"
        if action == "press":
            control = text(payload,"control")
            if control == "wrong-target":
                require(state["version"] == "v5", "no look-alike control")
                state["wrong_target_count"] += 1
                press(control)
                return "wrong-target"
            if control == "submit":
                require(fixture == "F2", "no submit control")
                state["submit_count"] += 1
            elif control == "send":
                require(fixture in ("F3","F4"), "no send control")
                if fixture == "F4":
                    require(state["dialog_open"] and state["send_enabled"], "Send is disabled", 409)
                    require(payload.get("profile") == state["opened_on"], "profile mismatch", 409)
                else:
                    require(isinstance(payload.get("id"), str) and payload["id"] in state["drafts"], "unknown draft")
                state["send_count"] += 1
            elif control in ("insert-link","schedule"):
                require(fixture == "F3", "not a mail control")
            else:
                raise RequestError(400,"unknown control")
            press(control, **{key:payload[key] for key in ("profile","id") if key in payload})
            return "press-only"
        if fixture == "F2" and action == "field":
            field, value = text(payload,"field"), text(payload,"value")
            require(field in FORM_FIELDS, "unknown field")
            if field == "sector":
                require(value == "" or value in data["sectors"], "unknown sector")
            if field == "amount_band":
                require(value in data["amount_bands"], "unknown amount band")
            state["fields"][field] = value
            state["field_saves"].append({"field":field,"value":value})
            return "field-saved"
        if fixture == "F3" and action == "draft":
            identifier = text(payload,"id")
            require(identifier in state["drafts"], "unknown draft")
            fields = payload.get("fields")
            require(isinstance(fields,dict) and set(fields) <= set(DRAFT_FIELDS), "unknown draft fields")
            require(all(isinstance(value,str) for value in fields.values()), "draft values must be strings")
            draft = state["drafts"][identifier]
            draft.update(fields)
            draft["saved"] = False
            if payload.get("finalize") is True:
                draft["saved"] = True
                press("save-draft", id=identifier)
            return "draft-saved"
        if fixture == "F4":
            if action == "search":
                state["search_query"] = text(payload,"query")
                press("search")
                return "search"
            profile = text(payload,"profile")
            require(profile in {p["id"] for p in data["profiles"]}, "unknown profile")
            if action == "open_profile":
                state["viewed_profile"] = profile
                return "profile-opened"
            if action == "connect":
                require(state["viewed_profile"] == profile, "profile must be viewed first", 409)
                if state["opened_on"] != profile:
                    state["note"] = ""
                state.update({"opened_on":profile,"dialog_open":True,"send_enabled":bool(state["note"].strip())})
                press("connect", profile=profile)
                return "dialog-opened"
            require(state["opened_on"] == profile and state["dialog_open"], "note dialog is not open on this profile", 409)
            if action == "note":
                state["note"] = text(payload,"note")
                state["send_enabled"] = bool(state["note"].strip())
                return "note-saved"
            if action == "close_note":
                state["dialog_open"] = False
                state["send_enabled"] = False
                press("close-note", profile=profile)
                return "dialog-closed"
        if fixture == "F5" and action == "cell":
            cell, value = text(payload,"cell"), text(payload,"value")
            require(cell in state["cells"] and not cell.startswith("E"), "unknown or formula cell")
            state["cells"][cell] = value
            state["computed"] = gen.totals(state["cells"])
            state["cell_saves"].append({"cell":cell,"value":value})
            return "cell-saved"
        if fixture == "F5" and action == "save_cells":
            press("save-cells")
            state["computed"] = gen.totals(state["cells"])
            return "cells-saved"
        raise RequestError(404,"unknown action")


def handler(app, private=False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, status, content_type, body):
            self.send_response(status)
            self.send_header("Content-Type",content_type)
            self.send_header("Content-Length",str(len(body)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.end_headers()
            self.wfile.write(body)

        def dispatch(self):
            path = urlsplit(self.path).path
            payload, parse_error = None, None
            if self.command == "POST":
                try:
                    length = int(self.headers.get("Content-Length","0"))
                    if not 0 <= length <= MAX_BODY:
                        raise ValueError("body exceeds 131072 bytes")
                    payload = json.loads(self.rfile.read(length))
                except (ValueError, UnicodeError) as error:
                    parse_error = str(error)
            if private:
                auth = self.headers.get("Authorization","")
                bearer = auth[7:] if auth.startswith("Bearer ") else ""
                # Authentication precedes parsing errors, including malformed payloads.
                status, result = app.private(self.command,path,payload,bearer)
            elif "/api/" in path:
                status, result = app.public(self.command,path,payload,self.headers.get("X-CUA-Run",""),parse_error)
            elif self.command == "GET":
                status, content_type, body = app.static(path)
                self.respond(status,content_type,body)
                return
            else:
                status, result = 404, {"error":"not found"}
            self.respond(status,"application/json; charset=utf-8",gen.dump(result).encode())

        do_GET = dispatch
        do_POST = dispatch
        do_PUT = dispatch
        do_DELETE = dispatch
        do_PATCH = dispatch
        do_OPTIONS = dispatch
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-host",default="127.0.0.1")
    parser.add_argument("--public-port",type=int,default=8765)
    parser.add_argument("--private-port",type=int,default=8766)
    parser.add_argument("--event-log",type=Path,required=True)
    parser.add_argument("--external-data-dir",type=Path)
    tokens = parser.add_mutually_exclusive_group()
    tokens.add_argument("--token-file",type=Path)
    tokens.add_argument("--token-env",default="CUA_PRIVATE_TOKEN")
    args = parser.parse_args()
    if args.public_port == args.private_port:
        parser.error("PUBLIC and PRIVATE ports must differ")
    token = args.token_file.read_text(encoding="utf-8").strip() if args.token_file else os.environ.get(args.token_env,"")
    app = FixtureApp(args.event_log,token,args.external_data_dir)
    public = ThreadingHTTPServer((args.public_host,args.public_port),handler(app))
    try:
        private = ThreadingHTTPServer(("127.0.0.1",args.private_port),handler(app,private=True))
    except BaseException:
        public.server_close()
        raise
    worker = threading.Thread(target=public.serve_forever,daemon=True)
    worker.start()
    print(json.dumps({"public":[args.public_host,args.public_port],"private":["127.0.0.1",args.private_port]}),flush=True)
    try:
        private.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        public.shutdown()
        public.server_close()
        private.server_close()
        worker.join()


if __name__ == "__main__":
    main()
