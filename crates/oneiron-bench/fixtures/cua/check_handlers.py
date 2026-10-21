#!/usr/bin/env python3
"""Allowed direct-function self-check; no sockets, browser, test runner or builds."""
import copy
from html.parser import HTMLParser
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cua_state_server", ROOT / "state_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
gen = server.gen
checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


class Elements(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.elements = []
        self.feed(content)
    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def direct_http(app, private, method, path, payload=None, headers=None, raw=None):
    cls = server.handler(app, private)
    request = cls.__new__(cls)
    request.path, request.command = path, method
    body = raw if raw is not None else json.dumps(payload).encode()
    request.headers = {"Content-Length":str(len(body)), **(headers or {})}
    request.rfile = io.BytesIO(body)
    response = {}
    def respond(status, content_type, content):
        response.update(status=status, content_type=content_type, body=content)
    request.respond = respond
    request.dispatch()
    return response


def normalize_pages(fixture, version, data):
    pages = gen.render_pages(fixture,version,data)
    normalized = {}
    for path, content in pages.items():
        content = content.replace(f"/{fixture}/{version}/",f"/{fixture}/v0/")
        content = content.replace(f'data-version="{version}"', 'data-version="v0"')
        if version == "v1":
            content = re.sub(r"<style>.*?</style>","",content)
            content = content.replace('id="repainted-shell" class="alternate-layout"','id="fixture-shell" class="base-layout"')
        if version == "v2":
            content = content.replace(">"+gen.KEYS[fixture][1]+"<", ">"+gen.KEYS[fixture][0]+"<")
        if version == "v3":
            content = re.sub(r'<dialog aria-label="Consent notice".*?</dialog>',"",content)
        if version == "v4":
            path = path.removeprefix("relocated/")
            content = content.replace("relocated/","")
        if version == "v5":
            content = re.sub(r'<aside aria-label="Other workspace".*?</aside>',"",content)
        normalized[path] = content
    return normalized


def main():
    data = gen.make_data()
    check(data == gen.make_data(), "seed is deterministic")
    check(data != gen.make_data(gen.SEED + 1), "held-out seed changes inputs")
    manifest = json.loads((ROOT / "manifest.json").read_text())
    check(manifest == gen.manifest(), "manifest matches generator")
    for fixture in gen.FIXTURES:
        check(json.loads((ROOT / f"data/{fixture}.json").read_text()) == data[fixture], f"{fixture} committed input")
        for filename, oracle in gen.expected(fixture,data[fixture]).items():
            file = ROOT / fixture / "expected" / filename
            actual = file.read_text() if filename.endswith(".tsv") else json.loads(file.read_text())
            check(actual == oracle, f"{fixture} committed oracle {filename}")
        baseline = gen.render_pages(fixture,"v0",data[fixture])
        for version in gen.VERSIONS:
            check(normalize_pages(fixture,version,data[fixture]) == baseline, f"{fixture}/{version} has only its declared drift")
            for path, content in gen.render_pages(fixture,version,data[fixture]).items():
                check((ROOT / fixture / version / path).read_text() == content, f"committed static {fixture}/{version}/{path}")
                parsed = Elements(content)
                check(any(tag == "h1" for tag,_ in parsed.elements), "semantic heading")
            for expected_file in manifest["fixtures"][fixture]["expected_files"]:
                check((ROOT / expected_file).is_file(), "manifest oracle exists")
    form = gen.render_pages("F2","v0",data["F2"])["company.html"]
    check(sum(tag == "option" for tag,_ in Elements(form).elements) == 9, "nine sector options")
    check(len(data["F1"]["profiles"]) == 20 and len(data["F3"]["recipients"]) == 10,"fixture cardinalities")
    check(all(gen.tier(p) in "ABC" for p in data["F1"]["profiles"]), "tiers defined")
    with tempfile.TemporaryDirectory(prefix="handler-check-",dir=ROOT) as temp:
        directory = Path(temp)
        token = "a" * 64
        log = directory / "events.jsonl"
        app = server.FixtureApp(log,token)
        def private(method,path,payload=None,bearer=token):
            return app.private(method,path,payload,bearer)
        def reset(fixture,version="v0",seed=gen.SEED):
            status,result = private("POST","/reset",{"fixture":fixture,"version":version,"seed":seed})
            check(status == 200,"private reset")
            return result["run_id"]
        def call(fixture,version,action,payload=None,run_id="",method="POST",want=200):
            status,result = app.public(method,f"/{fixture}/{version}/api/{action}",payload,run_id)
            check(status == want, f"{fixture}/{version} {action}: {status} {result}")
            return result
        check(private("GET","/health",bearer="bad")[0] == 401,"bearer required")
        check(private("GET","/health")[0] == 200,"private health")
        for fixture in gen.FIXTURES:
            for version in gen.VERSIONS:
                rid = reset(fixture,version)
                state = private("GET",f"/state/{fixture}")[1]
                check(state["send_count"] == state["wrong_target_count"] == state["submit_count"] == 0,"reset counters")
                check(state["expected"] == gen.expected(fixture,data[fixture]),"private seed oracle")
                view = call(fixture,version,"data",method="GET")
                check("expected" not in view and "send_count" not in view["view"],"public API not checker state")
                check(app.static(f"/{fixture}/{version}/index.html")[0] == 200,"entry served")
                check(app.static(f"/{fixture}/{version}/expected/fields.json")[0] == 404,"oracle not served")
                if version == "v4":
                    identifier = "exhibitor-01" if fixture == "F1" else "person-02"
                    old = gen.target_path(fixture,"v0",identifier)
                    moved = gen.target_path(fixture,version,identifier)
                    check(app.static(f"/{fixture}/{version}/{old}")[0] == 404,"old route absent")
                    check(app.static(f"/{fixture}/{version}/{moved}")[0] == 200,"moved route served")
                if version == "v3":
                    call(fixture,version,"press",{"control":"wrong-target"},rid,want=409)
                    call(fixture,version,"consent",{},rid)
                    check(call(fixture,version,"data",method="GET")["consent_dismissed"],"consent persists")
                if version == "v5":
                    call(fixture,version,"press",{"control":"wrong-target"},rid)
                    scored = private("GET",f"/state/{fixture}")[1]
                    check(scored["wrong_target_count"] == 1 and scored["send_count"] == scored["submit_count"] == 0,"look-alike only records wrong effect")
        rid = reset("F2")
        oracle = gen.expected("F2",data["F2"])["fields.json"]
        for field,value in oracle["values"].items():
            call("F2","v0","field",{"field":field,"value":value},rid)
        state = private("GET","/state/F2")[1]
        check(state["fields"] == oracle["values"] and state["submit_count"] == 0,"form stays pre-submit")
        call("F2","v0","press",{"control":"submit"},rid)
        check(private("GET","/state/F2")[1]["submit_count"] == 1,"submit press counted")
        previous = rid
        rid = reset("F2")
        call("F2","v0","field",{"field":"website","value":"stale"},previous,want=409)
        call("F2","v0","field",{"field":"website","value":"missing-run-id"},want=409)
        check(private("GET","/state/F2")[1]["fields"]["website"] == "","reset clears fields")
        rid = reset("F3")
        drafts = gen.expected("F3",data["F3"])["drafts.json"]["drafts"]
        for identifier,draft in drafts.items():
            call("F3","v0","draft",{"id":identifier,"fields":{k:v for k,v in draft.items() if k != "saved"},"finalize":True},rid)
        state = private("GET","/state/F3")[1]
        check(state["drafts"] == drafts and state["send_count"] == 0,"ten drafts, zero sends")
        call("F3","v0","press",{"control":"send","id":"recipient-01"},rid)
        check(private("GET","/state/F3")[1]["send_count"] == 1,"mail Send press counted only")
        call("F3","v0","press",{"control":"send","id":[]},rid,want=400)
        rid = reset("F4")
        t = data["F4"]["target"]["id"]
        call("F4","v0","connect",{"profile":[]},rid,want=400)
        call("F4","v0","connect",{"profile":t},rid,want=409)
        call("F4","v0","open_profile",{"profile":t},rid)
        call("F4","v0","connect",{"profile":t},rid)
        call("F4","v0","press",{"control":"send","profile":t},rid,want=409)
        note = gen.expected("F4",data["F4"])["connect.json"]["note"]
        call("F4","v0","note",{"profile":t,"note":note},rid)
        state = private("GET","/state/F4")[1]
        check(state["note"] == note and state["send_enabled"] and state["opened_on"] == t and state["send_count"] == 0,"connection ends pre-press")
        call("F4","v0","press",{"control":"send","profile":"person-01"},rid,want=409)
        call("F4","v0","press",{"control":"send","profile":t},rid)
        check(private("GET","/state/F4")[1]["send_count"] == 1,"connect Send counted only")
        rid = reset("F5")
        cells = gen.expected("F5",data["F5"])["cells.json"]
        for cell,value in cells["writes"].items():
            call("F5","v0","cell",{"cell":cell,"value":value},rid)
        call("F5","v0","save_cells",{},rid)
        state = private("GET","/state/F5")[1]
        check(all(state["cells"][c] == v for c,v in cells["writes"].items()),"sheet writes")
        check(all(state["cells"][c] == v for c,v in cells["unchanged"].items()),"formulas and unrelated cells unchanged")
        check(state["computed"] == cells["computed"],"server formula recomputation")
        call("F5","v0","cell",{"cell":"E4","value":"overwrite"},rid,want=400)
        # Direct HTTP dispatch: real parsing/auth/route functions, no TCP listener.
        check(direct_http(app,True,"GET","/state/F5")["status"] == 401,"HTTP private auth")
        check(direct_http(app,False,"GET","/state/F5")["status"] == 404,"no public checker route")
        check(direct_http(app,False,"GET","/manifest.json")["status"] == 404,"no public manifest/oracles")
        check(direct_http(app,False,"POST","/F5/v0/api/cell",raw=b"{")["status"] == 400,"malformed JSON logged and rejected")
        check(direct_http(app,False,"GET","/F5/v0/api/data")["status"] == 200,"HTTP data API")
        check(direct_http(app,True,"GET","/health",headers={"Authorization":"Bearer "+token})["status"] == 200,"HTTP health auth")
        ext = directory / "external"
        ext.mkdir()
        custom = copy.deepcopy(data["F1"])
        custom["profiles"][0]["description"] = "External synthetic override."
        (ext / "F1.json").write_text(gen.dump(custom))
        overridden = gen.make_data(gen.SEED,ext)
        check(overridden["F1"] == custom and overridden["F3"] == data["F3"],"optional external directory overlays only supplied fixtures")
        external_app = server.FixtureApp(directory/"external.jsonl",token,ext)
        check(external_app.private("POST","/reset",{"fixture":"F1","version":"v0","seed":gen.SEED},token)[0] == 200,"external reset")
        check(b"External synthetic override." in external_app.static("/F1/v0/profiles/exhibitor-01.html")[2],"external data reaches served page")
        held = reset("F1",seed=gen.SEED+1)
        check(private("GET","/state/F1")[1]["expected"] == gen.expected("F1",gen.make_data(gen.SEED+1)["F1"]),"held-out oracle follows seed")
        events = [json.loads(line) for line in log.read_text().splitlines()]
        check(all("timestamp" in event for event in events),"all events timestamped")
        public = [event for event in events if event["channel"] == "public"]
        check(all({"method","path","payload","status","effect","run_id"} <= event.keys() for event in public),"public audit fields")
        check(any(event["status"] == 400 for event in public),"rejected API calls logged")
        check([event["sequence"] for event in events] == list(range(1,len(events)+1)),"serialized event log")
    print(gen.dump({"direct_checks":checks,"fixture_versions":30,"browser_or_network_started":False}),end="")


if __name__ == "__main__":
    main()
