# MicroVM artifact build recipe

This builds inputs for `FirecrackerHostConfig`; it does not provision a host or
claim a VM boot. No command downloads, installs, changes host configuration, or
uses a loop device. Run from the engine checkout. Outputs must be new directories.

## Required preinstalled tools

- Native Linux x86-64 Rust toolchain from `rust-toolchain.toml`, C linker and the
  normal Cargo environment. The native guest executable is **not** a macOS binary.
  A cross build needs a separately provisioned Linux target and linker. The recipe
  does not install either. Use the factory Cargo wrapper in a factory worktree.
- Kernel build: trusted Linux release archive and independently verified SHA256,
  GNU make, C compiler/binutils, flex, bison, bc, Perl, Python and the development
  libraries required by the selected release/config (normally OpenSSL and libelf).
- Rootfs build: `readelf`, `mke2fs`, `debugfs`, Python >=3.11 with tar data filters.
  Dynamic builds need their exact ELF interpreter and dependency closure, supplied
  explicitly; the recipe never runs `ldd` or the supplied ELF.

## Build the guest executable and ABI conformance component

```text
cargo build -p oneiron-guest --release --locked
cargo test -p oneiron-guest --locked
```

On a native Linux host the output is `target/release/oneiron-guest`. A static
Linux build may be used instead if its target/linker are already installed.
No automatic host install, target install, or dev fallback is allowed.

The same tool also runs on macOS for **local ABI conformance only**:

```text
cargo run -p oneiron-guest -- --write-conformance target/conformance.wasm
```

The generated component calls `metadata` using `conformance-handle` at
`https://api.example.com`, then proposes `/mnt/workspace/result.txt`. It copies
source text rather than interpreting it. WAT/native Wasmtime execution is not
QuickJS proof. C13 ONE-2464 owns the real QuickJS guest and must target the shared
`crates/oneiron/wit/code-run.wit` ABI; C04 does not edit that ticket.

## Build a pinned kernel

Supply a Linux x86-64 release archive whose SHA256 was verified from a trusted
release channel. The exact digest is a required argument, never inferred as a
trust decision from unverified bytes. No kernel version/hash is fabricated here.
The receipt records that source pin and the exact resulting kernel/config hashes.

```text
python3 scripts/microvm/build.py kernel --archive /input/linux.tar.xz --sha256 VERIFIED_SHA256 --epoch 1700000000 --jobs 2 --output target/guest-kernel
```

The recipe starts at x86_64_defconfig and merges `kernel.config`. It refuses when
required built-in drivers or disabled-module policy do not survive olddefconfig.
The output is the ELF `target/guest-kernel/kernel.elf`, suitable for Firecracker's
x86-64 kernel loader, not a compressed bzImage. The source archive is extracted
without escape paths or special files; safe internal release symlinks are kept.
It records the compiler, make, config and source-date epoch in the receipt.

## Build a read-only ext4 rootfs without root

Pin the already-built Linux executable with SHA256. Supply each loader/library
at its actual guest path. `readelf --program-headers --dynamic` lists those inputs.
For example (the library closure depends on the actual binary and toolchain):

```text
python3 scripts/microvm/build.py rootfs --agent target/release/oneiron-guest --sha256 VERIFIED_AGENT_SHA256 --library lib64/ld-linux-x86-64.so.2=/input/ld-linux-x86-64.so.2 --library usr/lib/libc.so.6=/input/libc.so.6 --library usr/lib/libm.so.6=/input/libm.so.6 --library usr/lib/libgcc_s.so.1=/input/libgcc_s.so.1 --epoch 1700000000 --output target/guest-rootfs
```

Static binaries need no `--library`. The recipe rejects Mach-O/non-x86-64 inputs,
missing explicit ELF dependencies, duplicate destinations and unsafe paths. It
stages `/sbin/oneiron-guest` and the required mountpoints, formats ext4 with
`mke2fs -d`, and normalizes inode ownership/times with debugfs. No mount or root is
needed. The resulting image is chmod 0444; Firecracker also attaches it read-only.
UUID, file hashes, image hash, epoch and size are recorded. Tool versions and
filesystem defaults can affect ext4 bytes: the receipt, not a claim of identical
bytes across arbitrary e2fsprogs releases, is the artifact identity.

## Produce the host-pinning manifest

Use a native build of oneiron-guest as a BLAKE3 digest tool (it only reads bytes):

```text
python3 scripts/microvm/build.py manifest --kernel target/guest-kernel/kernel.elf --rootfs target/guest-rootfs/rootfs.ext4 --component target/conformance.wasm --digest-tool target/release/oneiron-guest --output target/guest-artifacts.json
```

The manifest records BLAKE3/SHA256/length for each artifact and the canonical WIT
hash. Copy the BLAKE3 values into the corresponding host-owned config fields.
That config also requires pinned Firecracker/jailer paths, delegated cgroup v2
cpu/memory/pids controllers, private scratch/chroot roots, and dedicated non-root
uid/gid. Only an authorized privileged Linux process with KVM may boot it. The
recipe does not configure those shared boundaries.

## Native acceptance (requires authorized provisioning)

Set `ONEIRON_MICROVM_CONFIG`, `ONEIRON_MICROVM_TEST_KERNEL`,
`ONEIRON_MICROVM_TEST_ROOTFS`, `ONEIRON_MICROVM_TEST_COMPONENT` on the provisioned
Linux host, then explicitly run:

```text
cargo test -p oneiron --features microvm-firecracker firecracker_real_boot_returns_only_proposals -- --ignored
```

It must boot, resolve the credential only on the host, return a file-edit
proposal and leave base files unchanged. Unit/socket/LOCALTEST evidence does not
replace this run. A real JavaScript interpreter must additionally run the actual
first-party JavaScript/gated-write acceptance; the conformance component cannot.
