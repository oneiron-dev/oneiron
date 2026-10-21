#!/usr/bin/env python3
"""The house llama.cpp server's launch identity (FIX 7895, 6567 PR1b).

`serve-llama.sh` runs `prepare` once per launch, before it execs
llama-server. It mints a random 128-bit epoch, hashes what the launch loads
(every target and draft GGUF part llama.cpp reads, streamed, and the server
binary), reads the target's typed tokenizer metadata and chat templates, and
writes one immutable manifest of all of it, named by its own SHA-256, into a
directory that holds manifests only. It prints the arguments the launch adds,
one per line:

    --alias oneiron-llama/<epoch>/<manifest SHA-256>
    --path <the manifests directory>
    --ui

llama.cpp answers every request under that one alias (its `model`, on chat,
stream and native answers alike) and lists it as its model id; `--path`
serves the directory at the server's root, so `GET /<digest>.json` is the
manifest of the launch that answered. llama-server mounts `--path` only with
its web UI on, hence `--ui`; the static directory replaces the embedded UI.

Identity never stops the server. If anything here fails (an unwritable
directory, an unreadable file, a llama.cpp config file that sets an alias),
`prepare` warns on stderr and exits non-zero, and the launcher starts
llama-server as it would without it: no alias, no manifest.

The manifest is canonical JSON (keys sorted, compact, ASCII, no trailing
newline), schema 1. Its `identity` holds the digests the engine reads:

- `model`: the target GGUF's SHA-256, or for a split GGUF the SHA-256 of its
  parts' SHA-256s in load order;
- `tokenizer`: the target's typed `tokenizer.*` metadata, chat templates
  aside (each key, its GGUF type and its value's stored bytes);
- `runtime`: the `build` section: the binary's own SHA-256, with the source
  commit and CMake flags `build-llama.sh` recorded for exactly that binary;
- `template`: the `templates` section, the chat templates llama-server takes
  from the target GGUF, when no launch setting picks another;
- `cache_mode`: the `cache` section, the launch's context and slots with the
  digest of every setting it ran with, given only when the binary's source
  commit is known, so its defaults are.

A llama.cpp config file (`/etc/llama.cpp/config.ini` or the user's) can set
anything, so with one present `model`, `tokenizer` and `template` are left
out and the file's SHA-256 is listed. The manifest attests the launch, never
a call: a request's own template arguments, samplers or cache options are
not in it.

Commands:

    prepare --server BIN --manifest-dir DIR --configured-wire-id ID -- ARG...
    verify MANIFEST [--files]
    record-build BIN SOURCE_SHA [-- CMAKE_FLAG...]

It runs no model and downloads nothing.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import struct
import sys
from pathlib import Path

SCHEMA_VERSION = 1
BACKEND = "llama_cpp"
# The alias namespace the engine reads (oneiron::llm::parse_llama_alias).
ALIAS_PREFIX = "oneiron-llama/"
# Beside the binary: what build-llama.sh built it from.
BUILD_RECORD_SUFFIX = ".build.json"
HASH_CHUNK = 8 << 20

# llama.cpp reads its settings from config files, then LLAMA_ARG_*, then
# argv (common/arg.cpp, common_params_parse_ex).
ENV_PREFIX = "LLAMA_ARG_"
ALIAS_ENV = "LLAMA_ARG_ALIAS"
UI_ENV = ("LLAMA_ARG_UI", "LLAMA_ARG_NO_UI")
# Settings whose values may hold a credential: listed by their SHA-256.
CREDENTIAL_ENV = ("LLAMA_ARG_MCP_SERVERS_JSON", "LLAMA_ARG_MODEL_URL", "LLAMA_ARG_MMPROJ_URL")
# Settings that pick a chat template other than the target GGUF's own.
TEMPLATE_ENV = ("LLAMA_ARG_CHAT_TEMPLATE", "LLAMA_ARG_CHAT_TEMPLATE_FILE", "LLAMA_ARG_JINJA",
                "LLAMA_ARG_NO_JINJA")
TEMPLATE_ARGS = ("--chat-template", "--chat-template-file", "--no-jinja")
# A config file's keys for the alias: its env name, or an argument's name.
CONFIG_ALIAS_KEYS = (ALIAS_ENV, "alias", "a")
SYSTEM_CONFIG = Path("/etc/llama.cpp/config.ini")

GGUF_MAGIC = b"GGUF"
GGUF_VERSIONS = (2, 3)
GGUF_STRING = 8
GGUF_ARRAY = 9
GGUF_SCALAR_BYTES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
TOKENIZER_PREFIX = "tokenizer."
TEMPLATE_KEY = "tokenizer.chat_template"
TOOL_USE_TEMPLATE_KEY = "tokenizer.chat_template.tool_use"
SPLIT_COUNT_KEY = "split.count"
# llama.cpp's split naming (src/llama.cpp, llama_split_path).
SPLIT_NAME = re.compile(r"^(?P<prefix>.+)-(?P<index>\d{5})-of-(?P<count>\d{5})\.gguf$")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX32 = re.compile(r"[0-9a-f]{32}")


class IdentityError(Exception):
    """Why a launch's identity was not prepared, or a manifest did not verify."""


def warn(message):
    print(f"llama_identity: WARN {message}", file=sys.stderr, flush=True)


def canonical_manifest_bytes(value):
    """The canonical bytes of a manifest, or of one of its sections: keys
    sorted, compact separators, ASCII, no trailing newline."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def section_digest(section):
    return sha256_hex(canonical_manifest_bytes(section))


def sha256_file(path):
    """A file's size and the SHA-256 of its bytes, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


class GgufReader:
    """A GGUF file's header and metadata, read in order up to its tensors."""

    def __init__(self, stream):
        self.stream = stream

    def take(self, size):
        data = self.stream.read(size)
        if len(data) != size:
            raise IdentityError("truncated GGUF metadata")
        return data

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def value(self, kind, out):
        """Reads one value of GGUF type `kind`, appending its stored bytes to
        the bytearray `out` when there is one."""
        if kind == GGUF_STRING:
            head = self.take(8)
            body = self.take(struct.unpack("<Q", head)[0])
            parts = (head, body)
        elif kind == GGUF_ARRAY:
            head = self.take(12)
            inner, count = struct.unpack("<IQ", head)
            if out is not None:
                out += head
            if inner in GGUF_SCALAR_BYTES:
                body = self.take(GGUF_SCALAR_BYTES[inner] * count)
                if out is not None:
                    out += body
            else:
                for _ in range(count):
                    self.value(inner, out)
            return
        elif kind in GGUF_SCALAR_BYTES:
            parts = (self.take(GGUF_SCALAR_BYTES[kind]),)
        else:
            raise IdentityError(f"unknown GGUF value type {kind}")
        if out is not None:
            for part in parts:
                out += part


def read_gguf_identity(path):
    """What llama.cpp reads of a GGUF before its tensors that names the model's
    tokenizer and templates: the tokenizer digest (None without tokenizer
    metadata), the default and tool-use chat template bytes (None when absent)
    and the file's split count."""
    tokenizer = []
    templates = {}
    split_count = 1
    with open(path, "rb", buffering=1 << 20) as stream:
        reader = GgufReader(stream)
        if reader.take(4) != GGUF_MAGIC:
            raise IdentityError(f"{path} is not a GGUF file")
        version = reader.u32()
        if version not in GGUF_VERSIONS:
            raise IdentityError(f"{path} is GGUF version {version}, not one of {GGUF_VERSIONS}")
        reader.u64()  # the tensor count
        for _ in range(reader.u64()):
            key_bytes = reader.take(reader.u64())
            key = key_bytes.decode("utf-8")
            kind = reader.u32()
            wanted = key.startswith(TOKENIZER_PREFIX) or key == SPLIT_COUNT_KEY
            raw = bytearray() if wanted else None
            reader.value(kind, raw)
            if not wanted:
                continue
            if key in (TEMPLATE_KEY, TOOL_USE_TEMPLATE_KEY):
                if kind != GGUF_STRING:
                    raise IdentityError(f"{path}: {key} is not a string")
                templates[key] = bytes(raw[8:])
            elif key == SPLIT_COUNT_KEY:
                split_count = int.from_bytes(raw, "little")
            elif not key.startswith(TEMPLATE_KEY + "."):
                tokenizer.append((key_bytes, kind, bytes(raw)))
    digest = hashlib.sha256()
    for key_bytes, kind, raw in sorted(tokenizer):
        digest.update(struct.pack("<Q", len(key_bytes)) + key_bytes + struct.pack("<I", kind))
        digest.update(raw)
    return {
        "tokenizer": digest.hexdigest() if tokenizer else None,
        "default": templates.get(TEMPLATE_KEY),
        "tool_use": templates.get(TOOL_USE_TEMPLATE_KEY),
        "split_count": split_count,
    }


def gguf_parts(path):
    """Every file llama.cpp loads for the GGUF it is given at `path`, in load
    order, with what the first one names."""
    first = read_gguf_identity(path)
    count = first["split_count"]
    if count <= 1:
        return [Path(path)], first
    match = SPLIT_NAME.match(Path(path).name)
    if not match or int(match["index"]) != 1 or int(match["count"]) != count:
        raise IdentityError(f"{path} is one of {count} GGUF splits but not the first by llama.cpp's naming")
    directory = Path(path).parent
    return [directory / f"{match['prefix']}-{index:05d}-of-{count:05d}.gguf"
            for index in range(1, count + 1)], first


def artifact(path):
    """A GGUF as the manifest lists it: each part llama.cpp loads, by path,
    size and SHA-256, and the digest of the whole (the one part's own
    SHA-256, or the SHA-256 of the parts' SHA-256s in load order)."""
    parts, metadata = gguf_parts(path)
    listed = []
    for part in parts:
        size, digest = sha256_file(part)
        listed.append({"path": str(part), "size": size, "sha256": digest})
    whole = listed[0]["sha256"] if len(listed) == 1 else section_digest([p["sha256"] for p in listed])
    return {"parts": listed, "sha256": whole}, metadata


def template_entry(source):
    if source is None:
        return None
    return {"bytes_b64": base64.b64encode(source).decode("ascii"), "sha256": sha256_hex(source)}


def sets_alias(text):
    """Whether a llama.cpp config file names an alias in any section."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;[":
            continue
        key, sep, _ = line.partition("=")
        if sep and key.strip() in CONFIG_ALIAS_KEYS:
            return True
    return False


def config_files(env):
    """The llama.cpp config files this launch reads (common/arg.cpp,
    common_params_apply_system_config), by path and SHA-256. One that sets an
    alias fails the launch's identity: its alias could come first."""
    base = env.get("XDG_CONFIG_HOME") or os.path.join(env.get("HOME") or os.path.expanduser("~"), ".config")
    found = []
    for path in (SYSTEM_CONFIG, Path(base) / "llama.cpp" / "config.ini"):
        if path.exists():
            data = path.read_bytes()
            if sets_alias(data.decode("utf-8", "replace")):
                raise IdentityError(f"{path} sets a model alias")
            found.append({"path": str(path), "sha256": sha256_hex(data)})
    return found


def launch_env(env):
    """This launch's llama.cpp settings from the environment, by name: every
    LLAMA_ARG_ variable but the alias, which the launch sets. A value that may
    hold a credential is listed by its SHA-256."""
    settings = {}
    for name in sorted(env):
        if not name.startswith(ENV_PREFIX) or name == ALIAS_ENV:
            continue
        value = env[name]
        settings[name] = "sha256:" + sha256_hex(value.encode("utf-8")) if name in CREDENTIAL_ENV else value
    return settings


def build_identity(server):
    """The binary's SHA-256, with the source commit and CMake flags its build
    record names when that record is of exactly this binary."""
    _, binary = sha256_file(server)
    build = {"binary_sha256": binary, "source_sha": None, "cmake_flags": None}
    try:
        record = json.loads(Path(str(server) + BUILD_RECORD_SUFFIX).read_bytes())
    except (OSError, ValueError):
        return build
    flags = record.get("cmake_flags") if isinstance(record, dict) else None
    if (record.get("binary_sha256") == binary and isinstance(record.get("source_sha"), str)
            and HEX40.fullmatch(record["source_sha"]) and isinstance(flags, list)
            and all(isinstance(flag, str) for flag in flags)):
        build["source_sha"] = record["source_sha"]
        build["cmake_flags"] = flags
    return build


def argument(argv, name):
    """The value of `name` on the server's argv, its last one as llama.cpp
    takes it; None when absent."""
    value = None
    for index, arg in enumerate(argv[:-1]):
        if arg == name:
            value = argv[index + 1]
    return value


def templates_selected(launch):
    """Whether llama-server takes the target GGUF's own chat templates: no
    config file, setting or argument picks another (common/chat.cpp,
    common_chat_templates_init)."""
    return (not launch["config_files"]
            and not any(name in launch["env"] for name in TEMPLATE_ENV)
            and not any(arg in launch["argv"] for arg in TEMPLATE_ARGS))


def identity_of(manifest):
    """The identity digests a manifest's sections give."""
    launch = manifest["launch_execution"]
    configured = bool(launch["config_files"])
    templates = manifest["templates"]
    default = templates["default"]
    # llama.cpp renders with its own built-in template for an absent or
    # "chatml" default, which no GGUF bytes name.
    template_known = (templates_selected(launch) and default is not None
                      and base64.b64decode(default["bytes_b64"]) not in (b"", b"chatml"))
    identity = {
        "model": None if configured else manifest["target"]["sha256"],
        "tokenizer": None if configured else manifest["tokenizer"]["target"],
        "runtime": section_digest(manifest["build"]),
        "template": section_digest(templates) if template_known else None,
        "cache_mode": section_digest(manifest["cache"]) if manifest["build"]["source_sha"] else None,
    }
    return {key: value for key, value in identity.items() if value is not None}


def prepare_manifest(server, manifest_dir, wire_id, argv, env):
    """Hashes what the launch loads, mints its epoch and writes its manifest:
    (epoch, manifest digest, manifest path)."""
    if not wire_id:
        raise IdentityError("no configured wire id")
    configs = config_files(env)
    target_path = argument(argv, "--model")
    if target_path is None:
        raise IdentityError("the launch names no --model")
    draft_path = argument(argv, "--model-draft")
    context, slots = argument(argv, "--ctx-size"), argument(argv, "--parallel")
    if context is None or slots is None or int(slots) < 1:
        raise IdentityError("the launch names no --ctx-size or --parallel")
    target, target_meta = artifact(target_path)
    draft, draft_meta = artifact(draft_path) if draft_path else (None, None)
    build = build_identity(server)
    launch = {
        "argv": list(argv) + ["--path", str(manifest_dir), "--ui"],
        "env": launch_env(env),
        "config_files": configs,
        "cuda_visible_devices": env.get("CUDA_VISIBLE_DEVICES"),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "backend": BACKEND,
        "backend_epoch": secrets.token_hex(16),
        "configured_wire_id": wire_id,
        "target": target,
        "draft": draft,
        "tokenizer": {"target": target_meta["tokenizer"],
                      "draft": draft_meta["tokenizer"] if draft_meta else None},
        "templates": {"default": template_entry(target_meta["default"]),
                      "tool_use": template_entry(target_meta["tool_use"]),
                      "jinja": "--jinja" in argv},
        "build": build,
        "cache": {"ctx_total": int(context), "ctx_per_slot": int(context) // int(slots),
                  "slots": int(slots), "defaults_source_sha": build["source_sha"],
                  "launch_sha256": section_digest(launch)},
        "launch_execution": launch,
    }
    manifest["identity"] = identity_of(manifest)
    data = canonical_manifest_bytes(manifest)
    digest = sha256_hex(data)
    return manifest["backend_epoch"], digest, write_manifest(Path(manifest_dir), data, digest)


def write_manifest(directory, data, digest):
    """Writes `data` as `<digest>.json` in `directory`, whole or not at all,
    never over a manifest already there."""
    directory.mkdir(parents=True, exist_ok=True)
    final = directory / f"{digest}.json"
    temp = directory.parent / f".{directory.name}-{digest}.tmp"
    with open(temp, "xb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    try:
        os.link(temp, final)
    finally:
        temp.unlink()
    return final


def verify_manifest(path, files=False):
    """Checks a manifest: its name is the SHA-256 of its exact bytes, which
    are canonical; it is schema 1 for llama.cpp with a well-formed epoch; and
    its identity is what its sections give. With `files`, every listed GGUF
    part still hashes as listed. Returns (epoch, digest)."""
    path = Path(path)
    data = path.read_bytes()
    digest = sha256_hex(data)
    if path.name != f"{digest}.json":
        raise IdentityError(f"{path} is not named by the SHA-256 of its bytes, {digest}")
    manifest = json.loads(data)
    if canonical_manifest_bytes(manifest) != data:
        raise IdentityError(f"{path} is not canonical")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("backend") != BACKEND:
        raise IdentityError(f"{path} is not a schema {SCHEMA_VERSION} {BACKEND} manifest")
    epoch = manifest.get("backend_epoch")
    if not isinstance(epoch, str) or not HEX32.fullmatch(epoch):
        raise IdentityError(f"{path} has no well-formed epoch")
    if manifest.get("identity") != identity_of(manifest):
        raise IdentityError(f"{path}'s identity is not what its sections give")
    if files:
        for name in ("target", "draft"):
            for part in (manifest[name] or {}).get("parts", []):
                if sha256_file(part["path"]) != (part["size"], part["sha256"]):
                    raise IdentityError(f"{part['path']} no longer hashes as listed")
    return epoch, digest


def prepare_command(raw):
    if "--" not in raw:
        warn("prepare takes the server's arguments after --")
        return 2
    split = raw.index("--")
    parser = argparse.ArgumentParser(prog="llama_identity.py prepare")
    parser.add_argument("--server", required=True)
    parser.add_argument("--manifest-dir", required=True)
    parser.add_argument("--configured-wire-id", required=True)
    options = parser.parse_args(raw[:split])
    argv, env = raw[split + 1:], os.environ
    try:
        epoch, digest, final = prepare_manifest(options.server, options.manifest_dir,
                                                options.configured_wire_id, argv, env)
        if verify_manifest(final) != (epoch, digest):
            raise IdentityError("the manifest written is not the one prepared")
    except Exception as error:  # identity never stops the server
        warn(f"no launch identity ({type(error).__name__}: {error})")
        return 1
    if ALIAS_ENV in env:
        warn(f"{ALIAS_ENV} is set; the launch alias replaces it")
    for name in UI_ENV:
        if name in env:
            warn(f"{name} is set; --ui overrides it, as --path needs the UI on")
    for line in ("--alias", f"{ALIAS_PREFIX}{epoch}/{digest}", "--path", options.manifest_dir, "--ui"):
        print(line)
    return 0


def record_build(binary, source_sha, cmake_flags):
    """Writes `<binary>.build.json`: the binary's SHA-256, the source commit it
    was built from and its CMake flags."""
    if not HEX40.fullmatch(source_sha):
        raise IdentityError(f"{source_sha} is not a full commit SHA")
    _, digest = sha256_file(binary)
    record = {"binary_sha256": digest, "cmake_flags": list(cmake_flags), "source_sha": source_sha}
    path = Path(str(binary) + BUILD_RECORD_SUFFIX)
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(canonical_manifest_bytes(record))
    os.replace(temp, path)
    return path


def main():
    raw = sys.argv[1:]
    if raw[:1] == ["prepare"]:
        return prepare_command(raw[1:])
    if raw[:1] == ["record-build"] and len(raw) >= 3:
        # CMake flags start with "-": they come as they are, after an optional --.
        flags = raw[3:]
        print(record_build(raw[1], raw[2], flags[1:] if flags[:1] == ["--"] else flags))
        return 0
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="check a written manifest")
    verify.add_argument("manifest")
    verify.add_argument("--files", action="store_true", help="hash every listed GGUF part again")
    commands.add_parser("record-build", help="BIN SOURCE_SHA [-- CMAKE_FLAG...]: record what a binary was built from")
    args = parser.parse_args(raw)
    if args.command != "verify":
        parser.error("record-build takes BIN SOURCE_SHA [-- CMAKE_FLAG...]")
    epoch, digest = verify_manifest(args.manifest, files=args.files)
    print(f"{ALIAS_PREFIX}{epoch}/{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
