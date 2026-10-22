# Image release manifest: wire, signature, verification

Phase 1c of the guest image family (FIX 8253). Each built variant gets one
release manifest that names what was built, with what, and what it needs from
a host. A signature over that manifest is verified before an image is
installed or launched. **No signing key exists yet.** An unsigned image is
reported as the typed fact `image_signature_unavailable`, never as a pass,
and under the current policy nothing new refuses an install or a launch.

| File | What it is |
|---|---|
| `image-release.json` | The manifest: the signed payload, one per variant per build, written beside the artifacts. |
| `image-release.sig.json` | The detached signature envelope. It is absent today. |
| `release-manifest.schema.json` | The closed wire description: the manifest, plus `$defs.signature_envelope`. |
| `imagebuild/release_manifest.py` | The emitter (`build.py manifest`). |
| `deploy/firecracker/release.py` | The standalone Firecracker vault image's emitter: offline, over that image's built kernel and rootfs. |
| `oneiron_container::image_release` | The reader: the types, `verify_release`, the verifier seam, and the policy. `verify_release` reads no file; the `host_binding` child (`observe_bound_release`, `probe_host`) is the one host-side reader, for the launch doors (see Launch). |

## Emit

```sh
python3 build.py receipt  --work W --variant browser
python3 build.py manifest --work W --variant browser [--kernel vmlinux] [--signer-cmd CMD]
```

`manifest` reads the build record and `receipt.json`, then measures each
artifact itself. It never copies a digest from `release.toml`:

- the sha256 of `rootfs.tar`;
- the OCI archive: `index.json` is hashed, and every blob it reaches
  (manifest, config, layer) is hashed against its name;
- `rootfs.ext4`;
- the engine binaries inside the rootfs: `oneiron-guest`, `oneiron-fence`
  and `oneiron-browser-relay`, hashed from `rootfs.tar`;
- an operator-supplied kernel, given with `--kernel`.

Every measurement must equal the receipt, or the emitter refuses with
`error[pin-mismatch]`.

BLAKE3 is the digest the Firecracker host pins compare. Inside a builder work
dir, BLAKE3 comes from the tools tree's `b3sum` (`packages.toml [tools]`),
which runs through `mkosi box` as the build itself did; a tools tree without
`b3sum` is refused. Outside a builder (for example, artifacts copied by hand),
every `blake3` is `null` and the manifest carries the fact
`blake3_unmeasured`, so the gap is named, not silent.

Source pins (the kernel config and the unversioned contract sources) come from
the receipt's inputs, which the builder checked against the engine tree.
Contract revisions are the ones `release.toml [inputs.contracts]` pins.

Two VM capability facts are measured from `rootfs.tar`, never copied from a
source constant (FIX 9344): `vm_trusted_organ_builds_revision` is the
revision `release.toml` pins for the vault init when the image holds that
init at its pinned sha256, else 0; `vm_guest_runtime_revision` is 1 only when
the image holds the guest runtime's descriptor and every file it names at its
sha256, else 0, and a descriptor whose files do not all match is refused. The
current vault recipe stages no guest runtime, so its images name 0. Neither
fact gates an install, a launch or a boot.

### The standalone Firecracker vault image

```sh
python3 deploy/firecracker/release.py --kernel vmlinux --kernel-receipt kernel-receipt.json \
  --rootfs engine.ext4 --rootfs-receipt rootfs-receipt.json --release-inputs inputs.json \
  --output OUT [--signer-cmd CMD] [--b3sum PATH]
```

`deploy/firecracker/build.py` builds this image outside the family builder.
`release.py` emits its manifest offline, over the kernel and engine image
that build already made: it builds nothing and makes no vault or config disk,
so no mutable disk or secret goes into a release. It copies both into `OUT`
as `vmlinux` and `rootfs.ext4`, measures each again (SHA-256, and BLAKE3
through `b3sum`; without one it emits nothing), and checks each against its
receipt. What the receipts do not hold comes from `--release-inputs`, a JSON
file pinned for that build: `engine` (`commit`, `version`), the SHA-256 of
each engine binary that build made (`engine_binaries`, checked against the
rootfs receipt's inventory), and the contract revisions and source pins at
that commit; nothing is read from the current checkout. The two capability
facts come from the rootfs receipt's measured inventory. `receipt.json`
keeps both receipts and the inputs as `provenance`. The manifest names no
OCI form (`artifacts.oci: null`), since this image has none, and binds its
own rootfs and kernel bytes instead; its snapshot is not qualified. It
shares the emitter's schema check, exact-byte write and signing seam: with
no `--signer-cmd`, no envelope is written.

## Wire

All fields are required, and unknown fields are refused at every level. A
`null` is explicit, never an omitted key. Digests carry their algorithm:
`sha256:<64 hex>` or `blake3:<64 hex>`. Paths are relative to the manifest's
directory (artifacts) or to the repo root at `engine.commit` (source pins).
No path is absolute on the host.

| Field | Holds |
|---|---|
| `schema`, `kind` | `1`, `"oneiron-image-release"`. |
| `variant`, `arch` | Pack A's spelling (`base`, `vault`, `browser`, `desktop-cua`, `checker`, `generic-agent`); `"linux/amd64"`. |
| `generation` | The engine commit's first 12 hex, `-`, then the receipt sha256's first 16 hex. |
| `engine` | `commit` (40 hex) and the workspace `version`. |
| `contracts` | Guest protocol version, checker helper header version, WIT world, `vault` (the eight vault contract revisions, then the two measured VM capability facts `vm_trusted_organ_builds_revision` and `vm_guest_runtime_revision`, 0 or 1), `storage` (`abi_version`, `schema_version`, vault variant only, else `null`), and `unversioned` source pins for the native session, fence wire, fence supervisor and relay. |
| `artifacts.oci` | `reference` (a tag, not an identity), `index_digest`, `manifest_digest`, `config_digest` (the image id), `layer_digest`, `layer_diff_id`, and `archive` (a file). These identities are distinct: none stands in for another. Required: `null` only for the standalone Firecracker vault image, which names its kernel image; every builder output names its real OCI form. |
| `artifacts.rootfs_ext4` | A file: `path`, `bytes`, `sha256`, `blake3`. |
| `artifacts.kernel` | `config` (source pin) and `image` (a file, or `null`: the family builds no kernel). |
| `binaries` | `guest`, `fence`, `relay`: `{path, sha256}` inside the image, or `null` when the variant has none. A variant's other binaries are not roles here: desktop-cua's `cua-driver` and generic-agent's Bun, tsrs and launchers are bound by the rootfs hashes, and named with their pins and measured hashes in the receipt (`inputs.payloads`, `installed`, `source_builds`, `native`) and the SBOM. |
| `sbom` | The build's SPDX 2.3 JSON SBOM: `{media_type: "application/spdx+json", path: "sbom.spdx.json", sha256}`, measured again from the file and checked against the receipt; `null` for a build without one. The in-toto provenance statement (`provenance.json`) is named by the receipt. |
| `provenance` | The build receipt: `{media_type, path: "receipt.json", sha256}`. |
| `host` | `kvm` (true when every launch form needs `/dev/kvm`; only the vault), `kernel_floor` (from the fence's Landlock ABI floor: ABI 3 needs Linux 6.2), `landlock_abi_floor`, and `seccomp_user_notify` (fence plumbing). |
| `snapshot` | `qualified` (false), plus the image half of a snapshot's compatibility tuple: the rootfs and kernel BLAKE3, the guest protocol and the storage ABI. A snapshot restores only onto exact values; anything else cold-boots. |
| `facts` | What the emitter could not measure: `blake3_unmeasured`, or empty. |

## The signature covers the exact file bytes

The envelope signs the bytes of `image-release.json` as written, newline
included. Nothing re-serializes or canonicalizes the manifest. Signing never
rewrites the payload, and a reader verifies before it parses. Re-emitting a
manifest without `--signer-cmd` deletes any older envelope beside it, because
an envelope over other bytes would only read as an invalid signature.

The envelope (`image-release.sig.json`):

```json
{ "provider": "kms_hsm | sigstore_keyless | owner_hardware_key",
  "algorithm": "ecdsa-p256-sha256",
  "key_or_identity_ref": "<enrolled key id, or issuer + subject>",
  "signature": "<standard base64>",
  "certificate_or_bundle": "<optional: PEM chain or a whole Sigstore bundle>" }
```

It follows a Sigstore bundle's verification material: see
<https://docs.sigstore.dev/about/bundle/> and the formal `sigstore_bundle.proto`
in sigstore/protobuf-specs, media type
`application/vnd.dev.sigstore.bundle.v0.3+json`. That is what
`cosign sign-blob --bundle` writes for a blob. Three providers fill the same
fields, and no caller changes:

- **A. A KMS/HSM key after its ceremony.** `key_or_identity_ref` names the
  enrolled key, and `signature` is that key's signature over the bytes. The
  key never leaves the KMS.
- **B. Sigstore keyless with GitHub OIDC.** `certificate_or_bundle` carries
  the v0.3 bundle: the short-lived Fulcio certificate and the Rekor entry.
  `key_or_identity_ref` names the expected issuer and subject.
- **C. An owner-held hardware key.** Shaped as A.

A key reference or an embedded certificate is a lookup hint, never trust. The
verifier adapter decides from roots and identities it holds itself.

**The signing seam** is `--signer-cmd CMD`. The command reads the manifest
bytes on stdin and writes one envelope on stdout. The emitter checks the
envelope against `$defs.signature_envelope` and writes it. Nothing uses the
seam today.

**The verifying seam** is one Rust trait:

```rust
pub trait ReleaseSignatureVerifier {
    fn verify(&self, payload: &[u8], envelope: &SignatureEnvelope)
        -> Result<SignerIdentity, SignatureRefusal>;
}
```

The only shipped implementation is `NoVerifierConfigured`. Real adapters (KMS,
Sigstore, hardware) come with the crypto lane and implement this trait.

## Results and facts

```rust
verify_release(manifest_bytes, envelope: Option<&[u8]>, &ObservedArtifacts,
               &HostCapabilities, &dyn ReleaseSignatureVerifier) -> ReleaseVerification
```

The function parses the manifest. It compares each digest the **caller**
measured with the manifest's value; the function itself reads no file and
hashes nothing (the launch doors' host-side reader is under Launch). Against
a manifest with no OCI form, an observed OCI digest is `not_in_manifest`,
never a match; the rootfs and kernel digests are what bind such a manifest
to the bytes in use. It checks the host's observed capabilities against
`host`, and reads the signature. The result is never a bare success. Its
`signature` is one of:

| Outcome | Meaning |
|---|---|
| `verified { signer }` | An adapter verified the bytes against trust it holds. |
| `unavailable` | No envelope exists. Fact `image_signature_unavailable`. |
| `unverifiable { provider, refusal }` | An envelope is present, but no configured verifier handles it. |
| `invalid { refusal }` | The envelope is malformed, or the verifier refused it (`bad_signature`, `untrusted_signer`, `expired`, `revoked`). |

The fact codes are exact wire strings, each with a `const` of the same name:

| Fact | When |
|---|---|
| `image_release_manifest_absent` | No manifest is bound to the image: no binding map, or no entry for the selected identity. |
| `image_release_documents_unavailable` | The host's binding map cannot be read or parsed, or a document it binds to the selected image cannot be read. No manifest bytes were checked. Distinct from no binding, and from readable bytes that are not the schema. |
| `image_release_manifest_malformed` | The bytes are not the closed schema. |
| `image_identity_mismatch` | An observed variant or arch differs from the manifest's. |
| `image_artifact_mismatch` | An observed digest differs from the manifest's. |
| `image_artifacts_unbound` | No observed digest matched, so the manifest is not tied to the bytes in use. |
| `image_blake3_unmeasured` | The manifest carries `blake3_unmeasured`. |
| `image_host_capability_missing` | The host lacks a capability the image needs. |
| `image_host_capability_unobserved` | The caller did not observe a needed capability. |
| `image_storage_abi_older_than_host` | The image's engine is older than the vault data it would open. |
| `image_signature_unavailable` | No envelope exists. |
| `image_signature_unverifiable` | An envelope is present, but nothing configured can check it. |
| `image_signature_invalid` | The envelope is present and did not verify. |

These are typed facts in structured evidence. They are not Gate reason codes
and never go into `receipt_reasons`.

## Policy: observe only

```rust
pub const IMAGE_SIGNATURE_POLICY: ImageSignaturePolicy = ImageSignaturePolicy::ObserveOnly;
release_admission(&ReleaseVerification, ImageSignaturePolicy) -> ReleaseAdmission
```

`ObserveOnly` always admits and returns the facts. `RequireVerified` admits
only a verified signature over a manifest bound to the observed bytes, with no
fact left. It exists, but nothing selects it: it narrows what runs, so it
waits for an owner ruling, enrolled trust roots and a rollout. Every existing
pin, fence and image-match check stays exactly where it is and decides as
before. The observation never replaces a check, and no check falls back to
it.

## Launch

`observe_release(Option<ReleaseDocuments>, &ObservedArtifacts,
&HostCapabilities, &dyn ReleaseSignatureVerifier) -> ImageReleaseObservation`
is the one observe path. The launch doors reach it through one host-side
wrapper, `observe_bound_release(SelectedImage, &ObservedArtifacts,
&dyn ReleaseSignatureVerifier)` (`src/image_release/host_binding.rs`). Each
door calls it after its existing checks and before it starts the guest:

- `ContainerRuntime::start` and `ContainerRuntime::start_fenced`
  (`crates/oneiron-container/src/lib.rs`), selecting and observing the pinned
  image reference. Its digest matches the manifest's config, manifest or
  index digest: which one a local image id names depends on the runtime's
  store;
- `FirecrackerBackend::boot`, after `config.pins.verify`, observing the
  kernel and rootfs BLAKE3 pins. An OCI boot keeps the reference it was
  given from before the host's boot registry resolves it to artifacts: it
  selects and also observes that reference, and records it as
  `SessionManifest.image`. A raw boot selects by its pins;
- `firecracker/oci_session.rs` `start`, after `config.pins.verify`,
  selecting the image reference and observing it with the pins.

### The binding

`ONEIRON_IMAGE_RELEASE_BINDINGS` names a JSON map on the host. The wrapper
reads the map, and the documents it names, at every launch. Nothing is
cached, and no guest claim, tag or directory scan selects a document. The
map is one closed object from a selected immutable identity to that image's
documents:

```json
{
  "sha256:<64 hex>": {
    "manifest": "/srv/oneiron/images/browser/image-release.json",
    "envelope": null
  },
  "blake3:<kernel 64 hex>,blake3:<rootfs 64 hex>": {
    "manifest": "code/image-release.json",
    "envelope": "code/image-release.sig.json"
  }
}
```

- An OCI launch is keyed by the digest its pinned reference names: the
  local image id as configured, or the digest after `@`. Key it by the id
  the engine is configured with, which is the id the serving store answers
  (the manifest digest on a containerd docker store, the config digest on a
  classic store or a VM vault's podman store).
- A raw Firecracker boot is keyed by its host-pinned kernel and rootfs
  BLAKE3, kernel first, joined by a comma.
- `manifest` names the exact `image-release.json`, and `envelope` the
  detached `image-release.sig.json`, or `null` (or no key) for an unsigned
  release. A path is absolute, or relative to the map's directory. An
  unknown field makes the whole map unreadable.

| Host state | Observation |
|---|---|
| The variable is unset or empty, the map file does not exist, or the map has no entry for the selected identity | `image_release_manifest_absent`, `image_signature_unavailable`: no binding. |
| The map cannot be read or parsed, or the bound manifest or envelope cannot be read | `image_release_documents_unavailable`, `image_signature_unavailable`. `manifest.state` is `unavailable`, with a reason that names the document and the error, never a host path. |
| The documents are read | `verify_release` over their exact bytes, against the door's observed artifacts and the measured host. |

### Host capabilities

When documents are bound, the wrapper measures the host with
`probe_host()`, read-only:

- `arch` from the `uname` machine: `x86_64` is `linux/amd64`; any other
  machine has no `ImageArch` and stays unobserved;
- `kernel` from the `uname` release's `<major>.<minor>`;
- `kvm` from opening `/dev/kvm` read-write and asking `KVM_GET_API_VERSION`;
  no VM is created. A missing or denied device is `false`;
- `landlock_abi` from the query-only
  `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`;
  Landlock disabled at boot is ABI 0. The fence's installer never runs in
  the server;
- `seccomp_user_notify` from `SECCOMP_GET_ACTION_AVAIL` for
  `SECCOMP_RET_USER_NOTIF`; no filter is installed;
- `storage_abi` is never probed: it belongs to the vault data an engine
  would open, and these launches open none.

Any other probe failure stays unobserved (`None`), never a guess and never a
value copied from the manifest. The probe describes the host that runs the
engine and its containers. A Firecracker guest runs its own kernel, and its
in-image fence depends on that kernel: the host probe is not evidence of
the guest kernel's Landlock or seccomp floor.

The observation goes into `SessionManifest.image_release`. The session-manifest
receipt and the call outputs already carry that structure, as evidence,
separate from the fence evidence. Every observation has
`policy: observe_only` and `admitted: true`, and the launch proceeds exactly
as before: no binding state, document error, mismatch or missing capability
refuses, delays or fails a launch. A session record that predates the field
decodes with the absent observation.

## Install (LC)

Hypnos calls the same function before it imports an image. Its import step
reads the host-owned, root-only staged copies:

```rust
use oneiron_container::image_release::{
    observe_release, probe_host, ImageArch, ImageVariant, NoVerifierConfigured,
    ObservedArtifacts, ReleaseDocuments, Sha256Digest,
};
let observation = observe_release(
    Some(ReleaseDocuments { manifest: &manifest_bytes, envelope: envelope_bytes.as_deref() }),
    &ObservedArtifacts {
        variant: Some(ImageVariant::Browser),
        arch: Some(ImageArch::LinuxAmd64),
        oci_image_digest: Some(Sha256Digest::parse(&pinned_image_id)?),
        oci_archive_sha256: Some(Sha256Digest::from_bytes(rehashed_archive_sha256)),
        ..ObservedArtifacts::default()
    },
    &probe_host(),
    &NoVerifierConfigured,
);
// Record `observation` per image beside the provisioning fact.
// Under ObserveOnly, `observation.admitted` is true: the import proceeds as before.
```

A CLI wrapper prints the observation's JSON and exits 0 whenever the check
ran. Exit 0 is never a signature proof. In a pack, each image's
`image-release.json` (and its envelope, once one exists) travels beside that
image's archive and is listed by path and sha256.

For the launch doors, the provisioner then stages each imported image's
exact `image-release.json` (and envelope) in host custody, writes the
binding map (see Launch) keyed by the id the engine's config pins, and sets
`ONEIRON_IMAGE_RELEASE_BINDINGS` on the engine unit (FIX 9427). The map holds
paths only, never copies of release digests. The archive's measured config
digest and a docker store's id are different measurements: the release
lists both (`config_digest`, `manifest_digest`), and the launch matches
whichever one the configured pin names. No signature is enforced.
