# Merge queue checker image contract

The image a merge queue check runs in (FIX 6868). The engine starts one
guest per check under the `[merge_queue]` section, through the sandbox's
own selector (`select_backend_for_session(Untrusted, …)`): Firecracker on
a KVM host with it installed, else the OCI fenced container. The guest runs
as uid/gid 10001 under the engine fence with no network: every off-session
destination is denied (`network = "deny"`).

The guest's command is `checker.py`, the trusted helper. The engine sends
it the pinned Git tree of the exact commit under check, never the live
checkout, its `.git`, config, hooks or a host mount. The helper copies it
to `/tmp/queue-check/src`, runs the repository's frozen `.oneiron/checks.json`
commands there with exactly their argv and environment, and sends each
child's actual exit status and output back. It installs nothing and
fetches nothing; a program the image lacks holds the check, naming it.

## What the image provides

- `/usr/local/bin/oneiron-queue-check`: this directory's `checker.py`,
  root-owned and not writable by uid 10001, run by `/usr/bin/python3`.
- Python 3 at `/usr/bin/python3` and Git.
- The Rust toolchain the engine seed plan names: `cargo` under
  `/opt/cargo/bin`, `RUSTUP_HOME=/opt/rustup`, toolchain `1.96`
  (rust-toolchain.toml), and the native build dependencies the workspace's
  `cargo check --locked --workspace --all-features` needs (a C toolchain,
  pkg-config, the system libraries its `-sys` crates link).
- A dependency store preseeded from the baseline lockfile at
  `/opt/queue-check/cargo-home` (`cargo fetch --locked` at image build). The
  helper copies it into the plan's scratch `CARGO_HOME` before a command
  runs, so `--locked` resolves offline.
- For the Firecracker backend, the same image as a rootfs profile the host
  provisions (`crates/oneiron/src/code_sandbox/firecracker.rs`); for the OCI
  backend, the fence launcher named by `ONEIRON_FENCE_LAUNCHER`.

## Pin

No digest is invented here: the operator builds and pins the image, then
names it with the toolchain identities it holds:

```toml
[merge_queue]
runtime = "/usr/bin/docker"
image = "sha256:<64 hex>"
toolchain = { rust = "1.96.0", python = "3.x", dependency_store = "sha256:<store digest>" }
# Optional overrides of the sandbox's default guest limits. A workspace
# check needs far more memory and tmpfs than the defaults.
# memory_mib = 20480
# tmpfs_mib = 30720
```

Without the section a check answers that it needs configuration and names
the keys; it never runs on the host instead. On a host with no isolated
backend (a Mac) the check names `merge_queue.checker_backend`.

## The host opt-in

`checker_backend = "host"` runs the same helper as a host child with an
empty environment, over the same protocol, and needs an explicit
`helper` argv and `toolchain` pin:

```toml
[merge_queue]
checker_backend = "host"
helper = ["/usr/bin/python3", "/opt/oneiron/checker.py"]
toolchain = { rust = "1.96.0" }
```

The host child reaches what the host reaches; its receipts say
`network = "host"` and are never reused.
