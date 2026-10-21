#!/usr/bin/env python3
"""The Oneiron guest image family builder. Linux x86_64 only; no root, no daemon.

  build.py validate                       check release.toml, packages.toml and the lock agree
  build.py fetch   --repo R --mirror M --work W [--variant base ...] [--learn]
  build.py build   --repo R --mirror M --work W --variant tools|base|<variant>
  build.py receipt --work W --variant <variant>
  build.py manifest --work W --variant <variant> [--kernel K] [--signer-cmd CMD]
  build.py engine-commit                  print inputs.engine.commit

`fetch` is the only online phase: it fills the mirror (M) with every pinned
input and, with --learn on a fresh mirror, writes packages.lock.toml. `build`
re-enters itself in a user namespace with no network at all and builds from
the mirror. See README.md and docs/ops/guest-image-family.md.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from imagebuild import model as model_mod  # noqa: E402
from imagebuild import pipeline, receipt, release_manifest  # noqa: E402
from imagebuild.fetch import Mirror  # noqa: E402
from imagebuild.util import BuildError, HostRefusal, log, userns_root  # noqa: E402


def _host() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise HostRefusal("fetch and build run on a Linux x86_64 host only (a fleet host, never a Mac)")
    if sys.version_info < (3, 11):
        raise HostRefusal("python3 3.11 or newer is required")


def _enter_userns(*, network: bool) -> None:
    """Re-executes this command as root of a fresh single-uid user namespace."""
    if userns_root():
        return
    if os.getuid() == 0:
        raise HostRefusal("run build.py as a regular user: it needs no root and takes none")
    argv = ["unshare", "--user", "--map-root-user", "--mount", *([] if network else ["--net"]),
            "--", sys.executable, *sys.argv]
    env = dict(os.environ, ONEIRON_IMAGES_USERNS="1", ONEIRON_IMAGES_OFFLINE="0" if network else "1")
    sys.stdout.flush()
    os.execvpe("unshare", argv, env)


def _paths(args) -> tuple[Path, Mirror, Path]:
    repo = Path(args.repo).resolve()
    mirror = Mirror(Path(args.mirror).resolve())
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    return repo, mirror, work


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    sub.add_parser("engine-commit")
    fetch = sub.add_parser("fetch")
    build = sub.add_parser("build")
    for cmd in (fetch, build):
        cmd.add_argument("--repo", required=True, help="a git checkout holding inputs.engine.commit")
        cmd.add_argument("--mirror", required=True, help="the retained input mirror")
        cmd.add_argument("--work", required=True, help="scratch and artifact directory")
    fetch.add_argument("--variant", action="append", default=None, choices=model_mod.BUILDABLE[1:])
    fetch.add_argument("--learn", action="store_true",
                       help="first run only: record unpinned hashes and write packages.lock.toml")
    build.add_argument("--variant", required=True, choices=model_mod.BUILDABLE)
    rec = sub.add_parser("receipt")
    rec.add_argument("--work", required=True)
    rec.add_argument("--variant", required=True, choices=model_mod.BUILDABLE[1:])
    man = sub.add_parser("manifest", help="write image-release.json from a built variant and its receipt")
    man.add_argument("--work", required=True)
    man.add_argument("--variant", required=True, choices=model_mod.BUILDABLE[1:])
    man.add_argument("--kernel", default=None, help="an operator-supplied kernel image to list and hash")
    man.add_argument("--signer-cmd", default=None,
                     help="the signing seam: reads the manifest bytes on stdin, writes one envelope on stdout; "
                          "unused today (no signing key exists)")
    args = parser.parse_args()

    try:
        model = model_mod.Model.load()
        if args.command == "validate":
            for note in model_mod.validate(model):
                print(f"note: {note}")
            print("validate: ok")
            return 0
        if args.command == "engine-commit":
            print(model.engine_commit())
            return 0
        if args.command == "receipt":
            work = Path(args.work).resolve()
            record = pipeline.load_record(work, args.variant)
            pipeline.check_record_inputs(model, record)
            path, sha = receipt.write(model, record, Path(record["artifacts"]))
            log(f"receipt {path} sha256 {sha}")
            print(receipt.release_block(record, sha))
            return 0
        if args.command == "manifest":
            work = Path(args.work).resolve()
            if release_manifest.in_builder(work):
                # b3sum runs in the tools tree as the build ran it; the
                # namespace keeps the network for a signer command.
                _host()
                _enter_userns(network=True)
            kernel = Path(args.kernel) if args.kernel else None
            path, sha = release_manifest.emit(model, work, args.variant, kernel=kernel, signer_cmd=args.signer_cmd)
            log(f"manifest {path} sha256 {sha}")
            print(path)
            return 0
        _host()
        model_mod.validate(model)
        if args.command == "fetch":
            _enter_userns(network=True)
            repo, mirror, work = _paths(args)
            pipeline.fetch(model, repo=repo, mirror=mirror, work=work, variants=args.variant or ["base"],
                           learn=args.learn)
            return 0
        _enter_userns(network=False)
        repo, mirror, work = _paths(args)
        record = pipeline.build(model, repo=repo, mirror=mirror, work=work, variant=args.variant)
        print(json.dumps({k: v for k, v in record.items() if k not in ("packages", "ownership")}, indent=2))
        return 0
    except BuildError as error:
        print(f"error[{error.kind}]: {error.message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
