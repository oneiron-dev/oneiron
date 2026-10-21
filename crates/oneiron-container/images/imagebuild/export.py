"""One assembled tree, exported twice from one deterministic tar.

The tar (rootfs.tar) carries the explicit ownership rule (owners.py), the
tree's modes and symlinks, and mtimes clamped to SOURCE_DATE_EPOCH, in sorted
order. The OCI image's single layer is that tar, gzipped. The Firecracker
rootfs is `mke2fs -d rootfs.tar` from the tools tree: a root-only ext4, no
partition table, no ESP, no UKI, its kernel kept separate. Both forms carry
identical owners, modes and bytes.

rootfs.members.tsv lists every tar member (path, type, mode, uid, gid, size,
mtime, and the file's sha256 or the link's target): the payload identity a
second build compares, independent of tar, gzip and ext4 framing.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from .util import BuildError, StepFailed, log, sha256_file

APIVFS = ("dev", "proc", "sys", "run", "tmp", "var/tmp")
MIB = 1 << 20
BLOCK = 4096
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


class OverBound(BuildError):
    kind = "over-bound"


class PathLeak(BuildError):
    kind = "path-leak"


def clean_apivfs(tree: Path) -> list[str]:
    removed = []
    for rel in APIVFS:
        root = tree / rel
        if root.is_dir() and not root.is_symlink():
            for child in sorted(root.iterdir()):
                removed.append(f"{rel}/{child.name}")
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
    return removed


def entries(tree: Path) -> list[str]:
    """Every path under tree, sorted, never following a symlink."""
    out = []
    for top, dirs, files in os.walk(tree):
        dirs.sort()
        rel_top = os.path.relpath(top, tree)
        for name in sorted(dirs + files):
            out.append(name if rel_top == "." else f"{rel_top}/{name}")
    return sorted(out)


def tree_digest(tree: Path) -> str:
    """Content identity of a tree: path, type, mode, size and bytes or link target.
    Ownership is left out: every mkosi tree here is single-uid on disk."""
    digest = hashlib.sha256()
    for rel in entries(tree):
        st = os.lstat(tree / rel)
        if stat.S_ISLNK(st.st_mode):
            body = "l:" + os.readlink(tree / rel)
        elif stat.S_ISREG(st.st_mode):
            body = "f:" + sha256_file(tree / rel)
        elif stat.S_ISDIR(st.st_mode):
            body = "d"
        else:
            body = f"o:{st.st_mode:o}"
        digest.update(f"{rel}\0{stat.S_IMODE(st.st_mode):o}\0{st.st_size if body[0] == 'f' else 0}\0{body}\n".encode())
    return digest.hexdigest()


def leak_scan(tree: Path, needles: list[str]) -> None:
    """Refuses a tree whose files name a build-machine path."""
    raw = sorted({n.encode() for n in needles if len(n) >= 5})
    width = max(len(n) for n in raw)
    hits = []
    for rel in entries(tree):
        path = tree / rel
        if not path.is_file() or path.is_symlink():
            continue
        tail = b""
        with open(path, "rb") as stream:
            while block := stream.read(1 << 20):
                window = tail + block
                for needle in raw:
                    if needle in window:
                        hits.append(f"{rel} holds {needle.decode()}")
                        break
                tail = window[-width:]
                if hits and hits[-1].startswith(rel + " "):
                    break
    if hits:
        raise PathLeak("build-machine paths in the image:\n  " + "\n  ".join(hits[:40]))


class _Hashing:
    """A read-through file wrapper: tar.addfile reads it, the sha256 sees the same bytes."""

    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def read(self, n: int = -1) -> bytes:
        data = self.stream.read(n)
        self.digest.update(data)
        return data


def rootfs_tar(tree: Path, dest: Path, epoch: int, owners: dict) -> dict:
    files = dirs = links = 0
    file_bytes = alloc = 0
    members = dest.with_name("rootfs.members.tsv")
    with tarfile.open(dest, "w", format=tarfile.PAX_FORMAT) as tar, open(members, "w") as listing:
        listing.write("# path\ttype\tmode\tuid\tgid\tsize\tmtime\tsha256|target\n")
        for rel in entries(tree):
            full = tree / rel
            info = tar.gettarinfo(str(full), arcname=rel)
            uid, gid, mode, _ = owners.get(rel, (0, 0, None, ""))
            info.uid, info.gid, info.uname, info.gname = uid, gid, "", ""
            if mode is not None:
                info.mode = mode
            info.mtime = min(int(info.mtime), epoch)
            body = ""
            if info.isreg():
                files += 1
                file_bytes += info.size
                alloc += -(-info.size // BLOCK) * BLOCK
                with open(full, "rb") as stream:
                    hashing = _Hashing(stream)
                    tar.addfile(info, hashing)
                body = hashing.digest.hexdigest()
                kind = "f"
            elif info.isdir():
                dirs += 1
                alloc += BLOCK
                tar.addfile(info)
                kind = "d"
            elif info.issym():
                links += 1
                alloc += BLOCK if len(info.linkname) > 59 else 0
                tar.addfile(info)
                kind, body = "l", info.linkname
            elif info.islnk():
                tar.addfile(info)
                kind, body = "h", info.linkname
            else:
                raise StepFailed(f"{rel}: unexpected file type in the image tree")
            listing.write(f"{rel}\t{kind}\t{info.mode:04o}\t{info.uid}\t{info.gid}\t"
                          f"{info.size if kind == 'f' else 0}\t{info.mtime}\t{body}\n")
    return {"path": str(dest), "sha256": sha256_file(dest), "bytes": dest.stat().st_size,
            "files": files, "dirs": dirs, "symlinks": links, "file_bytes": file_bytes,
            "allocated_estimate": alloc, "entries": files + dirs + links,
            "members": str(members), "members_sha256": sha256_file(members)}


def _blob(layout: Path, data: bytes) -> tuple[str, int]:
    digest = hashlib.sha256(data).hexdigest()
    (layout / "blobs" / "sha256" / digest).write_bytes(data)
    return digest, len(data)


def _json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _deterministic_tar(src: Path, dest: Path, epoch: int) -> None:
    with tarfile.open(dest, "w", format=tarfile.USTAR_FORMAT) as tar:
        for rel in entries(src):
            info = tar.gettarinfo(str(src / rel), arcname=rel)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.mode = 0o755 if info.isdir() else 0o644
            if info.isreg():
                with open(src / rel, "rb") as stream:
                    tar.addfile(info, stream)
            else:
                tar.addfile(info)


def oci(tar: dict, *, variant: str, image: dict, epoch: int, out: Path, annotations: dict) -> dict:
    """An OCI image layout tarball docker load accepts (index.json plus docker's manifest.json)."""
    layout = out / "oci"
    if layout.exists():
        shutil.rmtree(layout)
    (layout / "blobs" / "sha256").mkdir(parents=True)
    layer_path = layout / "layer.tar.gz"
    with open(tar["path"], "rb") as raw, open(layer_path, "wb") as sink:
        with gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0, compresslevel=6) as gz:
            shutil.copyfileobj(raw, gz, 1 << 20)
    layer = sha256_file(layer_path)
    layer_bytes = layer_path.stat().st_size
    layer_path.rename(layout / "blobs" / "sha256" / layer)
    created = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_config = {"Env": image.get("env", []), "Entrypoint": image["entrypoint"], "WorkingDir": "/",
                  "Labels": dict(annotations)}
    if image.get("user"):
        run_config["User"] = image["user"]
    config = {
        "architecture": "amd64", "os": "linux", "created": created, "config": run_config,
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{tar['sha256']}"]},
        "history": [{"created": created, "created_by": "crates/oneiron-container/images/build.py (mkosi)"}],
    }
    config_digest, config_size = _blob(layout, _json(config))
    manifest = {
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": f"sha256:{config_digest}", "size": config_size},
        "layers": [{"mediaType": OCI_LAYER, "digest": f"sha256:{layer}", "size": layer_bytes}],
        "annotations": {"org.opencontainers.image.created": created, **annotations},
    }
    manifest_digest, manifest_size = _blob(layout, _json(manifest))
    ref = f"oneiron-image-{variant}:candidate"
    index = {
        "schemaVersion": 2, "mediaType": OCI_INDEX,
        "manifests": [{
            "mediaType": OCI_MANIFEST, "digest": f"sha256:{manifest_digest}", "size": manifest_size,
            "platform": {"architecture": "amd64", "os": "linux"},
            "annotations": {"io.containerd.image.name": f"docker.io/library/{ref}",
                            "org.opencontainers.image.ref.name": "candidate"},
        }],
    }
    index_bytes = _json(index)
    (layout / "index.json").write_bytes(index_bytes)
    (layout / "oci-layout").write_bytes(_json({"imageLayoutVersion": "1.0.0"}))
    (layout / "manifest.json").write_bytes(_json([{
        "Config": f"blobs/sha256/{config_digest}", "RepoTags": [ref], "Layers": [f"blobs/sha256/{layer}"],
    }]))
    archive = out / f"{variant}.oci.tar"
    _deterministic_tar(layout, archive, epoch)
    return {
        "oci_index_digest": "sha256:" + hashlib.sha256(index_bytes).hexdigest(),
        "oci_manifest_digest": f"sha256:{manifest_digest}",
        "oci_config_digest": f"sha256:{config_digest}",
        "oci_layer_digest": f"sha256:{layer}",
        "oci_layer_diff_id": f"sha256:{tar['sha256']}",
        "oci_layer_bytes": layer_bytes,
        "oci_archive": str(archive),
        "oci_archive_sha256": sha256_file(archive),
        "oci_archive_bytes": archive.stat().st_size,
        "oci_ref": ref,
    }


def ext4_capacity(tar: dict) -> tuple[int, int]:
    """(capacity bytes, inode count): the files' blocks plus 5 %, inode tables and 96 MiB for
    journal, group metadata and slack, rounded up to 16 MiB. A computed size, not a budget."""
    inodes = tar["entries"] + tar["entries"] // 4 + 1024
    raw = tar["allocated_estimate"] + tar["allocated_estimate"] // 20 + inodes * 256 + 96 * MIB
    return -(-raw // (16 * MIB)) * (16 * MIB), inodes


def ext4(tar: dict, *, uuid: str, epoch: int, out: Path, cap: int, run_in_tools) -> dict:
    """The Firecracker rootfs, or, when its capacity would pass the engine's cap,
    none: the refusal is recorded (ext4_refused) and the OCI form stands alone."""
    capacity, inodes = ext4_capacity(tar)
    image = out / "rootfs.ext4"
    image.unlink(missing_ok=True)
    if capacity > cap:
        reason = (f"the rootfs needs {capacity} bytes of ext4 capacity, above the engine's {cap}-byte "
                  "Firecracker rootfs cap: no rootfs.ext4 is written and the cap does not move")
        log(f"refused: {reason}")
        return {"ext4_refused": reason, "ext4_needed_bytes": capacity, "ext4_inodes": inodes}
    env = {"SOURCE_DATE_EPOCH": str(epoch), "E2FSPROGS_FAKE_TIME": str(epoch)}
    run_in_tools([
        "mke2fs", "-q", "-F", "-t", "ext4", "-b", str(BLOCK), "-m", "0", "-N", str(inodes),
        "-d", tar["path"], "-U", uuid,
        "-E", f"root_owner=0:0,hash_seed={uuid},lazy_itable_init=0,lazy_journal_init=0,nodiscard",
        str(image), f"{capacity // 1024}k",
    ], env)
    run_in_tools(["e2fsck", "-f", "-n", str(image)], env)
    st = image.stat()
    log(f"ext4 {image}: {st.st_size} bytes capacity, {st.st_blocks * 512} allocated")
    return {"ext4": str(image), "ext4_sha256": sha256_file(image), "ext4_uuid": uuid,
            "sparse_capacity_bytes": st.st_size, "ext4_allocated_bytes": st.st_blocks * 512,
            "ext4_inodes": inodes}
