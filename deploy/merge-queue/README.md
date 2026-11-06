# Published merge-queue checker

`oneiron.toml` is an explicit server configuration for the published Linux x86_64
OCI checker. Its `[merge_queue].image` uses the immutable registry manifest digest,
not the local image config digest or a mutable tag. The normal configuration
loader reads this section when the operator selects the file with `serve --config`.
No engine default changes, and no running host is configured by this directory.

Use `/usr/bin/docker` only if it is the container CLI installed on the serving
host; otherwise set `runtime` to that CLI's absolute path. Copy the section into
the host's existing configuration to retain its other settings. The vault path,
listener, credentials and host fence remain the host's own configuration.
The guest limits remain the engine's existing defaults unless the operator
sets the existing per-key overrides.

## Publication identity

| Item | Value |
| --- | --- |
| Registry manifest | `sha256:6a29372e1df3cd3bc440d7c16635e326616c47f6503c8312ed3a60f46dc5993f` |
| Image config | `sha256:5f79afa1f4d54b17d8bd12e813c21d38ee5da929d3f538c4bdc50af1b2554672` |
| Engine source | `73994df04a6708a93b7b1cecd40a0fa73f97cd5b` |
| Seed Cargo.lock | `sha256:daaf587d1e960af654a1e3f6d4d62d4097d7afa07a62c47b984a0bd8ad3025f5` |
| Checker helper | `sha256:bcc3181eb89988eab7ea0b147fbe1df6ecfa331fd85b3c99d754b246d650ac81` |
| Fence | `sha256:da614d2cc51a1c360f2b8159202884398c0835b01373994409a1f3fa78f7d91f` |
| Guest | `sha256:de956d5949e3b519bdb0fd56e33bea25cc524d450b2a4ee1744098fe291403ac` |

The dependency store and guest/fence binaries are from that source commit,
not from the current checkout. Public access does not prove compatibility with
a newer guest protocol, host fence or Cargo.lock. Use a matching engine/image
release before enabling checks on a serving host. This pin does not update the
image-family release recipe, a Firecracker rootfs/profile, or guest artifact pins.
The Firecracker path still needs its own host-owned profile and matching pins.
See [the checker contract](../../crates/oneiron-container/guest/checker/README.md)
for provisioning and lockfile changes.

## Anonymous pull receipt

On 2026-11-05, fleet job `1105-211042-a128` on `nelly` pulled the exact registry
reference with `crane 0.22.1` and returned exit 0. It used a cleared environment,
a temporary HOME, and an empty temporary `DOCKER_CONFIG` that remained empty.
No registry credentials were supplied. The manifest digest and downloaded image
config matched the identities above. The resulting archive was removed after
verification. The image, helper and guest were not executed, rebuilt or uploaded.
This is a publication receipt, not a workspace compile or a checker-run result.
