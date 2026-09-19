#!/usr/bin/env python3
"""Fetch pinned, non-redistributed corpus inputs into explicit scratch space."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.parse
import urllib.request
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    args.output.mkdir(parents=True, exist_ok=True)
    def verify(item, data):
        if len(data) != item["size"]:
            raise ValueError("corpus length mismatch")
        actual = hashlib.sha256(data).hexdigest() if "sha256" in item else hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != item.get("sha256", item.get("git_blob_sha1")):
            raise ValueError("corpus hash mismatch")
    def fetch(item):
        name = Path(item["path"]).name
        path = args.output / name
        if not path.exists():
            url = manifest["dataset"] + "/resolve/" + manifest["revision"] + "/" + urllib.parse.quote(item["path"])
            with urllib.request.urlopen(url, timeout=120) as response:
                data = response.read(item["size"] + 1)
            verify(item, data)
            path.write_bytes(data)
        data = path.read_bytes()
        verify(item, data)
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise ValueError(f"ZIP integrity failure: {name}")
        return {"name": name, "sha256": hashlib.sha256(data).hexdigest()}
    with ThreadPoolExecutor(max_workers=4) as pool:
        files = list(pool.map(fetch, manifest["files"]))
    (args.output / "fetch-receipt.json").write_text(json.dumps({"manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(), "files": files}, indent=2) + "\n")
    print(f"verified {len(files)} corpus inputs")


if __name__ == "__main__":
    main()
