"""The published sdist must retain and build from the patched Cargo inputs.

Run in the packaging environment with maturin, the Rust toolchain, and cached
registry/git dependencies. The build runs offline in an extracted sdist with a
fresh target directory; it must not use sources or build artifacts from checkout.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
HEED = "crates/heed/vendor/heed-0.20.5"


def _run_packaging_command(command, *, cwd, env, timeout):
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # TimeoutExpired can carry bytes even when text=True.
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        pytest.fail(
            f"{error}\ncwd: {cwd}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            pytrace=False,
        )


@pytest.fixture(scope="module")
def python_sdist(tmp_path_factory):
    output = tmp_path_factory.mktemp("python-sdist")
    _run_packaging_command(
        [
            sys.executable, "-m", "maturin", "sdist",
            "--manifest-path", str(ROOT / "crates/oneiron-py/Cargo.toml"),
            "--out", str(output),
        ],
        cwd=ROOT / "crates/oneiron-py",
        env={**os.environ, "CARGO_NET_OFFLINE": "true"},
        timeout=180,
    )
    archives = list(output.glob("*.tar.gz"))
    assert len(archives) == 1
    return archives[0]


def test_python_sdist_contains_rust_and_cargo_inputs(python_sdist):
    with tarfile.open(python_sdist, "r:gz") as archive:
        files = [member.name for member in archive.getmembers() if member.isfile()]
        for required in [
            "oneiron-py/Cargo.toml",
            "oneiron-py/build.rs",
            "oneiron-py/src/lib.rs",
            "oneiron/Cargo.toml",
            "oneiron/src/lib.rs",
            "oneiron/src/memory/recall.rs",
            "oneiron-remote/Cargo.toml",
            "oneiron-remote/src/lib.rs",
            "oneiron-vault-contract/Cargo.toml",
            "oneiron-vault-contract/src/lib/mod.rs",
            "heed-0.20.5/Cargo.toml",
            "heed-0.20.5/src/lib.rs",
            "heed-0.20.5/src/env.rs",
            "heed-0.20.5/LICENSE-MIT",
            "Cargo.lock",
        ]:
            assert any(name.endswith("/" + required) for name in files), required
        assert any(name.endswith("/pyproject.toml") for name in files)
        roots = {Path(name).parts[0] for name in files}
        assert len(roots) == 1
        archive_root = roots.pop()
        assert f"{archive_root}/Cargo.toml" in files
        assert f"{archive_root}/Cargo.lock" in files
        # A same-version registry copy lacks ONE-218's descriptor-preserving
        # open seam. Require the patched source bytes at the root patch's path,
        # not just a Cargo.toml or an arbitrary file named heed/src/lib.rs.
        assert f"{archive_root}/{HEED}/Cargo.toml" in files
        for source in (ROOT / HEED / "src").rglob("*.rs"):
            name = f"{archive_root}/{source.relative_to(ROOT).as_posix()}"
            assert name in files, name
            assert archive.extractfile(name).read() == source.read_bytes(), name
        assert "open_with_cache_identity" in (
            archive.extractfile(f"{archive_root}/{HEED}/src/env.rs").read().decode()
        )


def test_python_sdist_builds_offline_with_vendored_heed(python_sdist, tmp_path):
    unpacked = (tmp_path / "unpacked").resolve()
    with tarfile.open(python_sdist, "r:gz") as archive:
        members = archive.getmembers()
        roots = {Path(member.name).parts[0] for member in members}
        assert len(roots) == 1
        # Reject traversal and links before extraction, including on Python
        # versions without tarfile's data filter.
        for member in members:
            assert member.isfile() or member.isdir(), member.name
            assert (unpacked / member.name).resolve().is_relative_to(unpacked)
        archive.extractall(unpacked, members=members)
    sdist_root = unpacked / roots.pop()
    assert not sdist_root.is_relative_to(ROOT)
    manifest = sdist_root / "crates/oneiron-py/Cargo.toml"
    env = {
        **os.environ,
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(tmp_path / "target"),
        "PYO3_PYTHON": sys.executable,
    }
    # Maturin narrows the workspace to the wheel's local dependencies but
    # carries the full workspace lockfile. Let Cargo normalize that lock offline
    # inside the extracted archive; preserving unused workspace entries is not
    # the packaging contract. Validate the local sources below, then lock the build.
    resolved = _run_packaging_command(
        [
            "cargo", "metadata", "--format-version", "1", "--offline",
            "--manifest-path", str(manifest),
        ],
        cwd=sdist_root,
        env=env,
        timeout=180,
    )
    metadata = json.loads(resolved.stdout)
    assert Path(metadata["workspace_root"]).resolve() == sdist_root
    heed_packages = [p for p in metadata["packages"] if p["name"] == "heed"]
    assert len(heed_packages) == 1
    heed = heed_packages[0]
    assert heed["version"] == "0.20.5"
    assert heed["source"] is None, "registry heed is not the audited local fork"
    assert Path(heed["manifest_path"]).resolve() == sdist_root / HEED / "Cargo.toml"
    assert heed["id"] not in metadata["workspace_members"]
    for package in metadata["packages"]:
        if package["source"] is None:
            assert Path(package["manifest_path"]).resolve().is_relative_to(sdist_root)
    engine = next(p for p in metadata["packages"] if p["name"] == "oneiron")
    node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == engine["id"])
    assert any(dep["name"] == "heed" and dep["pkg"] == heed["id"] for dep in node["deps"])

    # Resolve alone does not prove that all Rust/build-script inputs survived.
    # Build a real wheel using the normalized lock without further changes,
    # network access, or the checkout's target cache.
    wheels = tmp_path / "wheels"
    _run_packaging_command(
        [
            sys.executable, "-m", "maturin", "build", "--locked", "--offline",
            "--manifest-path", str(manifest), "--interpreter", sys.executable,
            "--out", str(wheels),
        ],
        cwd=sdist_root,
        env=env,
        timeout=1800,
    )
    assert len(list(wheels.glob("*.whl"))) == 1
