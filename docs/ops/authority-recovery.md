# Recovery material and vault authority

A world-recovery kit alone does not grant authority. Restoring world keys or
activating an owner anchor does not enroll an authority signer.

The core exports `world_keys::RecoveryAuthoritySigner`. It derives a distinct
Ed25519 key from an existing `RecoveryRootSeed` and the consuming vault's actual
authority vault id. The derivation context is
`oneiron/owner-recovery-authority/v1`; neither the recovery encryption key, the
owner anchor nor the checkpoint signing key is reused. The signer keeps no recovery-root seed
or serialized signing key, and its debug output contains public facts only.

## Before loss

1. Construct the signer with `RecoveryAuthoritySigner::from_seed` and the actual
   vault authority id. This is a pure material operation, not an enrollment.
2. The core-only `signer.enrollment(machine, owner)` produces the existing `OwnerKeyEnrollment`
   proof of possession for that vault, machine, owner and public key.
3. Pass it to the ordinary counted owner-key enrollment door with the owner's
   act, carrying install and live predecessor. That door owns its write
   transaction. Do not nest it in another writer or report successful enrollment
   before its receipt commits.

The signer exposes its public key, authority key, vault id and source root id.
Source-root identity is a binding fact, not an automatic current-pin gate.
Replacing a world kit is not revoking an enrolled authority key. The existing
authority fold and actual key revocation still decide its standing.

## After loss

`RecoveryAuthoritySigner::from_restored_kit` uses the existing RecoveryRoot kit
restore type. It applies no new piece-count, confirmation or current-owner-proof
requirement. A caller can also restore `RecoveryRootSeed` first and use
`from_seed`. The resulting key is the same one that needed explicit enrollment
before loss; a previously unenrolled or revoked key gains no standing.

The core-only authority-transcript signer is for the existing same-vault
`re_root_authority` writer's callback. It does not expose a general signing door
or implement the checkpoint-root signer trait.

The signer is the crypto/material supplier slice of FIX3934. It does not by
itself implement counted enrollment, lost-owner consumption or CLI/HTTP surfaces.

## Public Vault operations

Before loss, call `Vault::enrol_recovery_authority_key_as` with the live owner's
act, a live holding machine, the recovery seed and the existing predecessor's
signer. `enrol_recovery_authority_key_as_host` uses the normal host predecessor.
Both derive the key from this vault's actual authority identity and return only
a committed, counted `OwnerKeyEnrollmentReceipt`. They do not publish a kit or
make the separate kit-issue operation atomic with enrollment. Publish successful
recovery setup only after enrollment succeeds.

After loss, pass the existing `RestoredKitSecret` for a RecoveryRoot kit and the
fresh successor's `DeviceAuthority` to `Vault::recover_owner_authority_from_kit`.
It derives the same key using this vault's actual identity and runs the existing
ReRoot frontier joins and counted transition in one write transaction. It needs
neither the lost host's secret nor a current-owner proof. Unenrolled or revoked
keys and successors that fail the existing ReRoot rules still fail; no failed
call commits a recovery or a partial frontier join. The old roster retires under
the same normal ReRoot transition.

## Pre-loss CLI enrollment

After issuing a recovery-root kit, explicitly enroll its authority key while the
owner can still act:

```sh
oneiron recovery-kit enroll-authority --config serve.toml \
  --piece /private/kit/piece-1.txt --piece /private/kit/piece-2.txt
```

The holding machine is this install unless `--machine <32-hex-id>` names another
live holding machine. The command uses this install's existing host predecessor
and the existing self-host owner act. A hosted operator cannot turn a writer lease
into the vault owner's enrollment proof; the stopped command uses the normal
host-owner boundary, while the running HTTP door requires the owner's proof.
It returns the committed entry, machine and public key
as hex. It neither activates the world kit nor publishes or replaces its pieces.
Issuing the kit and enrolling its authority key are separate operations; issuance
alone is not successful recovery setup.

The usual `--unlock` and `--unlock-*` inputs open a sealed vault. A kit's
passphrase comes from `--secret-file` or stdin, never an argument. Exact kept
pieces count before choosing stdin; the unlock and kit passphrases cannot both
come from the same stream. No kit material is printed.

## Pre-loss HTTP enrollment

On the kit's own target install, `POST /v1/owner/recovery-kit/enroll-authority`
takes `target`, recovery-code `pieces`, an optional `passphrase`, and an optional
holding `machine` (the target when omitted). It requires the live owner's proof
and returns the same committed hex receipt as the command. Kit material stays in
this target's one request; no bare seed is accepted, stored, logged or returned.

This uses the existing kit recipient rules: hosted and managed installs take no
kit body, and the named target must prove to be this install and an allowed kit
recipient before its kit is parsed. It does not change those rules or make kit
issuance atomic with enrollment.

Post-loss CLI and HTTP recovery remain separate from these pre-loss enrollment
surfaces. The public Rust operations do not themselves claim those surfaces are
implemented, nor do they change kit confirmation, piece-count options, kit
replacement or ordinary key revocation.

## Post-loss CLI recovery

On a stopped copy of the vault, open its data with the existing unlock inputs and
recover authority with a kit whose distinct authority key was enrolled before loss:

```sh
oneiron recovery-kit recover-authority --config serve.toml \
  --piece /private/kit/piece-1.txt --piece /private/kit/piece-2.txt \
  --new-device /private/successor-device.json
```

`--new-device` is a JSON file, not stdin. It supplies every native successor field:

- `key`: an object with `suite` (`ed25519` or `p256`) and hex `public_key`.
  Ed25519 uses 32 bytes; P-256 uses canonical compressed SEC1 bytes.
- `transport_key_binding`: the actual 32-byte binding, in hex.
- `attestation`: an object with the actual `kind` and hex `evidence`.
- `tier`: `software`, `hardware` or `cloud_custodial`.
- `roles`: the native role-bit integer, with no inferred owner or admin role.

No field defaults to the lost host's key, a minted attestation, an empty binding
or an assumed tier. Supply the real successor public key and its truthful device
envelope. The file contains no signing seed or private key; custody of the
successor's private key remains the caller's responsibility. Its envelope is a
recovery target, not a credential or proof of possession for enrollment.

The command does not call the local-owner or host-predecessor door. It restores
kit material for the vault's actual authority identity, then calls the core
counted recovery operation. Only the previously enrolled, still-standing recovery
key authenticates it. Native successor, posture, role, freshness, frontier and
signature checks still apply. The JSON receipt contains the committed entry hash,
its authority vault id and its signer sequence. No kit material is printed.

This command needs an existing openable vault copy. It neither restores missing
vault data nor grants authority merely because world keys or a sealed bundle
were restored. Kit confirmation, piece-count options, kit replacement and
ordinary key revocation are unchanged. Its kit and data-unlock readers use the
same exact kept-piece and stdin rules as pre-loss enrollment.

## Post-loss HTTP recovery

On a non-hosted, non-managed open vault, `POST /v1/recovery/owner-authority`
takes one JSON object:

- `target`: the consuming vault's actual authority vault id, as 64 hex digits.
  It is not a mirror id, data-key id or machine id.
- `new_device`: the same fully explicit successor envelope as `--new-device`.
- `kit`: an object with recovery-code `pieces` and an optional `passphrase`.

The recovered, previously enrolled kit key authenticates this operation through
the core counted consume. No owner credential, lost-machine profile, mine proof
or host signing secret substitutes for that key. `new_device` is only the target,
not a bearer credential. The target id must match the same open vault's authority
fold before kit codes are parsed; the core also binds the actual vault identity
and counts the recovery in its own write transaction. The response is the same
committed recovery receipt as the command.

The shared existing kit posture guard rejects hosted and managed installs before
reading the secret body. The body streams through the existing transient-reader
ports, not a disk spool, and syntax errors never echo input. Request kit material
is wiped on drop, including target or device refusals. Existing listener body
policy remains; the endpoint adds no body-length cap, timeout or proof of
possession requirement. Do not put kit material in headers, URLs or logs.

The recipient distinction is Engine call 2026-11-05 10:50 JST, confirmed by L02 at
10:42:56 JST, based on CROSS-ARCH-0019 (`vault-20-unlock` and
`world-privacy-kit`): the recovery kit is the credential on a new machine. Asking
for the lost machine's profile proof would make recovery impossible. The owner
may overturn that call. The existing proved-install and world-recipient kit
transport rules remain unchanged for transfers between live machines, and the
pre-loss owner-authenticated HTTP enrollment keeps those rules.
