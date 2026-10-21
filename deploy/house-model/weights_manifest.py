#!/usr/bin/env python3
"""The house EXL3 target's weights manifest (FIX 7895, 6567 PR1b).

`prepare <model dir> <out>` runs once, when the weights are deployed: it
writes the canonical manifest of every weights shard the server loads (each
`*.safetensors` file in the directory, by relative name, byte size and
SHA-256, read in chunks). `verify <model dir> <manifest>` runs at every
launch, before the weights load: it hashes the installed shards again and
checks them against the manifest, refusing a missing, changed or unlisted
shard, and prints the manifest's digest. That digest, the SHA-256 of the
manifest's exact bytes, is the `model` digest in the server's cache identity
(`cache_usage.BackendIdentity`).

The manifest is canonical JSON (keys sorted, compact, ASCII, no trailing
newline): `{"files": [{"name", "sha256", "size"}, ...], "schema_version": 1}`,
files sorted by name. A manifest that is not canonical does not verify, so
its digest names exactly one shard list. The repository holds no real
manifest: the deployment writes it beside the weights.

It loads no model and downloads nothing.
"""
import hashlib
import json
import sys
from pathlib import Path

SCHEMA_VERSION = 1
# The files exllamav3 loads weights from.
SHARD_GLOB = "*.safetensors"
HASH_CHUNK = 8 << 20


class WeightsError(Exception):
    """Why installed weights do not match their manifest."""


def canonical_manifest_bytes(manifest):
    """Keys sorted, compact separators, ASCII, no trailing newline."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sha256_file(path):
    """A file's size and the SHA-256 of its bytes, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def shards(model_dir):
    """The weights shards in `model_dir`, by relative name, sorted."""
    directory = Path(model_dir)
    names = sorted(path.name for path in directory.glob(SHARD_GLOB) if path.is_file())
    if not names:
        raise WeightsError(f"{directory} holds no {SHARD_GLOB} weights")
    return directory, names


def prepare(model_dir, out):
    """Hashes every shard in `model_dir` and writes their manifest to `out`;
    returns its digest."""
    directory, names = shards(model_dir)
    files = []
    for name in names:
        size, digest = sha256_file(directory / name)
        files.append({"name": name, "sha256": digest, "size": size})
    data = canonical_manifest_bytes({"files": files, "schema_version": SCHEMA_VERSION})
    out = Path(out)
    temp = out.with_name(out.name + ".tmp")
    temp.write_bytes(data)
    temp.replace(out)
    return hashlib.sha256(data).hexdigest()


def verify(model_dir, manifest_path):
    """Checks the shards in `model_dir` against the manifest at
    `manifest_path`: every listed shard present with its size and SHA-256,
    and none unlisted. Returns the manifest's digest."""
    data = Path(manifest_path).read_bytes()
    try:
        manifest = json.loads(data)
    except ValueError as error:
        raise WeightsError(f"{manifest_path} is not JSON: {error}") from error
    if canonical_manifest_bytes(manifest) != data:
        raise WeightsError(f"{manifest_path} is not canonical")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise WeightsError(f"{manifest_path} is not a schema {SCHEMA_VERSION} weights manifest")
    listed = manifest.get("files")
    if not isinstance(listed, list) or not listed:
        raise WeightsError(f"{manifest_path} lists no shards")
    directory, names = shards(model_dir)
    expected = {entry.get("name"): entry for entry in listed if isinstance(entry, dict)}
    if len(expected) != len(listed) or sorted(expected) != names:
        raise WeightsError(f"{directory}'s shards are not the ones {manifest_path} lists")
    for name in names:
        entry = expected[name]
        if sha256_file(directory / name) != (entry.get("size"), entry.get("sha256")):
            raise WeightsError(f"{directory / name} does not hash as {manifest_path} lists")
    return hashlib.sha256(data).hexdigest()


def main():
    usage = "usage: weights_manifest.py prepare MODEL_DIR OUT | verify MODEL_DIR MANIFEST"
    if len(sys.argv) != 4 or sys.argv[1] not in ("prepare", "verify"):
        print(usage, file=sys.stderr)
        return 2
    command, model_dir, path = sys.argv[1:]
    try:
        digest = prepare(model_dir, path) if command == "prepare" else verify(model_dir, path)
    except (OSError, WeightsError) as error:
        print(f"weights_manifest: {error}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
