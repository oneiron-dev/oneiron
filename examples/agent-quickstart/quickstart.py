#!/usr/bin/env python3
"""Start a fresh vault and try private diary reads and shared recall."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parents[2]
STARTUP_TIMEOUT_SECS = 60


class SetupError(Exception):
    pass


def run(command, env, *, data=None):
    result = subprocess.run(
        [str(arg) for arg in command], cwd=REPO, env=env, text=True,
        input=data, stdin=subprocess.DEVNULL if data is None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise SetupError(
            f"{shlex.join(str(arg) for arg in command)} failed ({result.returncode}).\n"
            f"{result.stderr.strip()}\n{result.stdout.strip()}"
        )
    return result.stdout.strip()


def private_write(path, text):
    with path.open("x", encoding="utf-8") as output:
        output.write(text)
    path.chmod(0o600)


def stop(server):
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def wait_ready(server, url, log):
    # The port was free before this fresh vault's process was started.
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise SetupError(f"Vault server exited ({server.returncode}); read {log}.")
        try:
            with http.open(url + "/api/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.2)
    raise SetupError(
        f"Vault did not start within {STARTUP_TIMEOUT_SECS}s at {url}; read {log}. "
        "Check for a port conflict or a vault writer-lease error before restarting."
    )


def main():
    if sys.version_info < (3, 11):
        raise SetupError("Python 3.11 or newer is required; rerun with a supported python3 executable.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="Existing oneiron executable; otherwise install this checkout")
    parser.add_argument("--directory", type=Path, help="New directory for the vault, config and credentials")
    parser.add_argument("--keep-running", action="store_true", help="Leave the server running after the demo")
    args = parser.parse_args()
    if os.name != "posix":
        raise SetupError("This example needs Linux or macOS (the server's local credential-file support).")

    if sys.platform == "darwin" and not args.binary:
        raise SetupError("On macOS, use --binary with a signed oneiron that has a keychain access "
                         "group. A plain Cargo build cannot mint this vault's credential.")

    # Never let the caller's vault, auth, or model overrides affect this new vault.
    env = {key: value for key, value in os.environ.items() if not key.startswith("ONEIRON_")}
    cargo_bin = Path.home() / ".cargo" / "bin"
    env["PATH"] = str(cargo_bin) + os.pathsep + env.get("PATH", "")
    if not shutil.which("curl", path=env["PATH"]):
        raise SetupError("Missing curl. Install curl 7.76 or newer and put it on PATH; HTTP/MCP use it.")
    curl_version = run(["curl", "--version"], env).split()[1]
    if tuple(int(part) for part in curl_version.split(".")[:2]) < (7, 76):
        raise SetupError(f"curl {curl_version} is too old. Install curl 7.76 or newer and put it first on PATH.")

    if args.directory:
        directory = args.directory.expanduser().resolve()
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            raise SetupError(f"{directory} already exists. Choose a new --directory; no vault is overwritten.") from None
    else:
        directory = Path(tempfile.mkdtemp(prefix="oneiron-agent-")).resolve()
    directory.chmod(0o700)
    os.umask(0o077)
    print(f"Setup directory: {directory}", flush=True)

    if args.binary:
        found = shutil.which(args.binary, path=env["PATH"])
        if not found:
            raise SetupError(
                f"Missing oneiron binary: {args.binary}. Omit --binary to install this checkout, "
                "or pass the absolute path of an executable oneiron binary."
            )
        binary = Path(found).resolve()
    else:
        if not shutil.which("cargo", path=env["PATH"]):
            raise SetupError(
                "Missing cargo. Follow the noninteractive rustup installation commands in "
                "docs/agent-setup.md, then rerun. The checkout's rust-toolchain.toml selects "
                "the toolchain; alternatively pass --binary /absolute/path/to/oneiron."
            )
        install_root = directory / "install"
        command = ["cargo", "install", "--locked", "--path", str(REPO / "crates/oneiron-server"),
                   "--bin", "oneiron", "--root", str(install_root)]
        print("Installing this checkout (a source build can take hours)...", flush=True)
        result = subprocess.run(command, cwd=REPO, env=env, stdin=subprocess.DEVNULL)
        if result.returncode:
            raise SetupError(
                "Source installation failed; read Cargo's error above. Install the pinned Rust "
                "toolchain and native compiler prerequisites in docs/agent-setup.md, then rerun "
                "with a new directory. No server was started."
            )
        binary = install_root / "bin" / "oneiron"
    print(run([binary, "--version"], env), flush=True)

    # A new vault has no running server. Pick a port with no existing listener.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    config = directory / "oneiron.toml"
    credential = directory / "agent.cred"
    log = directory / "server.log"
    keys = json.dumps(str(directory / "keys"), ensure_ascii=False)
    private_write(config, f'host = "127.0.0.1"\nport = {port}\n'
                  f'auth_secret = "{secrets.token_hex(32)}"\n'
                  f'\n[keystore]\nbackend = "platform"\ndir = {keys}\n')
    print("Initializing a model-free vault and minting its agent credential...", flush=True)
    run([binary, "init", directory / "vault", "--config", config,
         "--embedder", "none", "--oneironer", "none"], env)
    # The two verbs it writes with; every read verb is allowed without naming.
    minted = json.loads(run([binary, "token", "agent", "--name", "agent-quickstart",
                             "--tier", "full-access",
                             "--verbs", "self.memory.diary,vault.notes.create",
                             "--out", credential, "--config", config], env))
    agent = minted["principal_ref"]

    paired = credential.read_text().strip()
    if not paired.startswith("v2.cred."):
        raise SetupError(f"{credential} is not a paired credential; use token agent --out, not a bearer secret.")
    slip, seed = paired.removeprefix("v2.cred.").rsplit(".", 1)
    client_env = dict(env, ONEIRON_SECRET="v2.slip." + slip, ONEIRON_BINDING_KEY=seed)

    with log.open("x", encoding="utf-8") as output:
        server = subprocess.Popen(
            [str(binary), "serve", "--config", str(config)], cwd=REPO, env=env,
            stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True,
        )
    success = False
    try:
        wait_ready(server, url, log)

        def api(verb, body):
            try:
                reply = run([binary, "api", "--base-url", url, "raw", "POST",
                             "/v1/core/facade/" + verb, "--data", "-"],
                            client_env, data=json.dumps(body))
            except SetupError as error:
                raise SetupError(
                    f"{error}\nIf unreachable, start `oneiron serve --config {config}` and check {log}. "
                    "If auth is refused, use this vault's paired slip AND binding seed, not auth_secret. "
                    "For an expired/revoked credential, stop this server and re-mint token agent "
                    "with the same config/name/tier and a new --out file, then restart."
                ) from None
            return json.loads(reply)

        diary_text = f"Agent setup completed unattended. Diary marker: diary{secrets.token_hex(8)}."
        diary_saved = api("self.memory.diary", {"content": diary_text})
        diary = api("self.memory.diary.query", {"agent": agent, "reason": "Verify quickstart diary entry"})
        if diary["state"] != "granted" or not any(
            entry["id"] == diary_saved["entry_id"] and entry["markdown"] == diary_text
            for entry in diary["entries"]
        ):
            raise SetupError(f"Private diary read did not return entry {diary_saved['entry_id']}; read {log}.")
        print(f"Read back from its private diary: {diary_saved['entry_id']}\n{diary_text}", flush=True)

        marker = "quickstart" + secrets.token_hex(8)
        content = f"Agent setup completed unattended. Recall marker: {marker}."
        note = api("vault.notes.create", {"kind": "research", "markdown": content})
        saved = {"entry_id": note["id_hex"]}  # The NOTE create receipt calls this id_hex.
        recalled = api("vault.recall", {"query": marker, "effort": "light", "limit": 5})
        matching = [item for item in recalled["items"]
                    if marker in item["value_text"]
                    and saved["entry_id"] in item["provenance"]["source_revision_ids"]]
        if not matching:
            raise SetupError(f"Recall did not return the saved research note {saved['entry_id']}; read {log}.")
        print(f"Saved and recalled research note: {saved['entry_id']}\n{matching[0]['value_text']}", flush=True)

        mcp_args = ["mcp", "--url", url, "--surface", "tool-first", "--credential-file", str(credential)]
        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "oneiron-agent-quickstart", "version": "1"},
        }}
        reply = json.loads(run([binary, *mcp_args], env, data=json.dumps(initialize) + "\n"))
        if "error" in reply or "protocolVersion" not in reply.get("result", {}):
            raise SetupError(f"MCP connection failed: {json.dumps(reply)}")

        private_write(directory / "mcp.json", json.dumps({"mcpServers": {"oneiron": {
            "command": str(binary), "args": mcp_args,
        }}}, indent=2) + "\n")
        private_write(directory / "connection.json", json.dumps({
            "binary": str(binary), "url": url, "config": str(config),
            "credential_file": str(credential), "pid": server.pid, "log": str(log),
            "diary_agent": agent, "diary_id": diary_saved["entry_id"],
            "memory_id": saved["entry_id"], "recall_query": marker,
        }, indent=2) + "\n")
        print(f"MCP connected. Client config: {directory / 'mcp.json'}", flush=True)
        print(f"MCP protocol: {reply['result']['protocolVersion']}", flush=True)
        print(f"Connection details: {directory / 'connection.json'}", flush=True)
        print("MCP command: " + shlex.join([str(binary), *mcp_args]), flush=True)
        if args.keep_running:
            print(f"Vault remains running at {url}. Stop it with: kill {server.pid}", flush=True)
        else:
            print("Stopping the example server. Use --keep-running to leave it available to an agent.", flush=True)
        success = True
    finally:
        if not (success and args.keep_running):
            stop(server)


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, ValueError, KeyError) as error:
        print(f"oneiron agent setup: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("oneiron agent setup: interrupted; the example server was stopped.", file=sys.stderr)
        sys.exit(130)
