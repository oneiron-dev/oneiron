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

This is the crypto/material supplier slice of FIX3934. Counted enrollment and
lost-owner consume integration, plus CLI/HTTP surfaces, are separate lane work.
This document does not claim those paths are implemented by the supplier alone.
