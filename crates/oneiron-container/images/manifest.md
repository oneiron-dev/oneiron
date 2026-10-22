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
| `oneiron_container::image_release` | The reader: the types, `verify_release`, the verifier seam, and the policy. |

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
measured with the manifest's value; the module itself reads no file and
hashes nothing. Against a manifest with no OCI form, an observed OCI digest
is `not_in_manifest`, never a match; the rootfs and kernel digests are what
bind such a manifest to the bytes in use. It checks the host's observed capabilities against `host`,
and reads the signature. The result is never a bare success. Its `signature`
is one of:

| Outcome | Meaning |
|---|---|
| `verified { signer }` | An adapter verified the bytes against trust it holds. |
| `unavailable` | No envelope exists. Fact `image_signature_unavailable`. |
| `unverifiable { provider, refusal }` | An envelope is present, but no configured verifier handles it. |
| `invalid { refusal }` | The envelope is malformed, or the verifier refused it (`bad_signature`, `untrusted_signer`, `expired`, `revoked`). |

The fact codes are exact wire strings, each with a `const` of the same name:

| Fact | When |
|---|---|
| `image_release_manifest_absent` | No manifest is bound to the image. This is today's state at every launch door. |
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
is the one observe path. Each launch door calls it after its existing checks
and before it starts the guest:

- `ContainerRuntime::start` and `ContainerRuntime::start_fenced`
  (`crates/oneiron-container/src/lib.rs`), observing the pinned image
  reference. Its digest matches the manifest's config, manifest or index
  digest: which one a local image id names depends on the runtime's store;
- `FirecrackerBackend::boot`, after `config.pins.verify`, observing the
  kernel and rootfs BLAKE3 pins;
- `firecracker/oci_session.rs` `start`, after `config.pins.verify`, observing
  the pins and the image reference.

The observation goes into `SessionManifest.image_release`. The session-manifest
receipt and the call outputs already carry that structure, as evidence,
separate from the fence evidence. No host-owned binding from an image to its
release documents exists yet, so every door passes `None`. Each launch records
`image_release_manifest_absent` and `image_signature_unavailable` with
`policy: observe_only` and `admitted: true`, and the launch proceeds exactly
as before. A session record that predates the field decodes with that same
absent observation.

## Install (LC)

Hypnos calls the same function before it imports an image. Its import step
reads the host-owned, root-only staged copies:

```rust
use oneiron_container::image_release::{
    observe_release, HostCapabilities, ImageArch, ImageVariant, NoVerifierConfigured,
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
    &HostCapabilities { arch: Some(ImageArch::LinuxAmd64), ..HostCapabilities::default() },
    &NoVerifierConfigured,
);
// Record `observation` per image beside the provisioning fact.
// Under ObserveOnly, `observation.admitted` is true: the import proceeds as before.
```

A CLI wrapper prints the observation's JSON and exits 0 whenever the check
ran. Exit 0 is never a signature proof. In a pack, each image's
`image-release.json` (and its envelope, once one exists) travels beside that
image's archive and is listed by path and sha256.
