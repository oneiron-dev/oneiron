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

CLI/HTTP wiring is separate lane work. These public Rust operations do not claim
that those surfaces are implemented, nor do they change kit confirmation,
piece-count options, kit replacement or ordinary key revocation.
