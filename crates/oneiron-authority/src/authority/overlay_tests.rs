//! The authority overlay's wire census and signed codec promises.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;

use super::op_samples::{OP_KIND_NAMES, every_op_sample, op_kind_name};
use super::*;

/// Census Part A, minus whole overlay leaves and their descendants.
/// Empty paths name op-map roots; `*` names any array or tuple element.
const SCAFFOLD_PATHS: &[(&str, &[&str], &str)] = &[
    ("slip_mint", &[], "operation map"),
    ("slip_mint", &["kind"], "operation discriminator"),
    ("slip_mint", &["slip_id"], "Opaque slip id"),
    ("slip_mint", &["vault_id"], "Vault identity digest"),
    ("slip_mint", &["parent_id"], "Opaque parent slip id"),
    (
        "slip_mint",
        &["holder_ref"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["binding_key"],
        "Holder proof verification key",
    ),
    ("slip_mint", &["issued_at"], "Timestamp"),
    ("slip_mint", &["expires_at"], "Timestamp"),
    ("slip_mint", &["ttl_secs"], "Duration"),
    ("slip_mint", &["single_use"], "Rule-selecting boolean"),
    (
        "slip_mint",
        &["actor_class"],
        "Closed human/agent/system rule tag",
    ),
    ("slip_mint", &["org_ref"], "scaffold under the owner ruling"),
    ("slip_mint", &["grant_ref"], "Opaque grant EntityId hex"),
    (
        "slip_mint",
        &["invitation_ref"],
        "Opaque invitation EntityId hex",
    ),
    ("slip_mint", &["share_ref"], "Opaque share EntityId hex"),
    (
        "slip_mint",
        &["delegation"],
        "scaffold under the owner ruling",
    ),
    ("slip_mint", &["comm"], "Closed reach ceiling enum"),
    ("slip_mint", &["renews"], "Opaque slip lineage id"),
    (
        "slip_mint",
        &["trusted_contact"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["seat_claim"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["minting_member"],
        "scaffold under the owner ruling",
    ),
    ("slip_mint", &["scope"], "scaffold under the owner ruling"),
    (
        "slip_mint",
        &["scope", "worlds"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "worlds", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "facets"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "facets", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "bands"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "bands", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "audience"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "audience", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "verbs"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "verbs", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["scope", "sensitivity"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["delegation", "owner_ref"],
        "scaffold under the owner ruling",
    ),
    ("slip_mint", &["delegation", "approved_at"], "Timestamp"),
    ("slip_mint", &["delegation", "wall_expires_at"], "Timestamp"),
    (
        "slip_mint",
        &["delegation", "repairs"],
        "Closed repair actions",
    ),
    (
        "slip_mint",
        &["delegation", "repairs", "*"],
        "Closed repair rule tag",
    ),
    (
        "slip_mint",
        &["trusted_contact", "person"],
        "scaffold under the owner ruling",
    ),
    (
        "slip_mint",
        &["trusted_contact", "version"],
        "Naming epoch/version",
    ),
    ("slip_mint", &["seat_claim", "attempt"], "Opaque attempt id"),
    (
        "slip_mint",
        &["seat_claim", "attempt_count"],
        "Attempt sequence counter",
    ),
    ("slip_revoke", &[], "operation map"),
    ("slip_revoke", &["kind"], "operation discriminator"),
    ("slip_revoke", &["slip_id"], "Opaque slip id"),
    ("slip_consume", &[], "operation map"),
    ("slip_consume", &["kind"], "operation discriminator"),
    ("slip_consume", &["slip_id"], "Opaque slip id"),
    ("slip_grant_revoke", &[], "operation map"),
    ("slip_grant_revoke", &["kind"], "operation discriminator"),
    ("slip_grant_revoke", &["grant_ref"], "Opaque entity id"),
    (
        "slip_grant_revoke",
        &["membership_receipt"],
        "Validated canonical EntityId hex receipt link",
    ),
    ("removal_archive_consume", &[], "operation map"),
    (
        "removal_archive_consume",
        &["kind"],
        "operation discriminator",
    ),
    ("removal_archive_consume", &["slip_id"], "Opaque slip id"),
    (
        "removal_archive_consume",
        &["member"],
        "scaffold under the owner ruling",
    ),
    ("genesis", &[], "operation map"),
    ("genesis", &["kind"], "operation discriminator"),
    ("genesis", &["device"], "Device verification scaffold"),
    ("genesis", &["device", "key"], "Verification key map"),
    (
        "genesis",
        &["device", "key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "genesis",
        &["device", "key", "public_key"],
        "Public verification bytes",
    ),
    (
        "genesis",
        &["device", "transport_key_binding"],
        "Transport public-key binding digest",
    ),
    (
        "genesis",
        &["device", "attestation"],
        "scaffold under the owner ruling",
    ),
    (
        "genesis",
        &["device", "attestation", "kind"],
        "scaffold under the owner ruling",
    ),
    ("genesis", &["device", "tier"], "Closed authority tier"),
    (
        "genesis",
        &["device", "roles"],
        "Rule-selecting role bits, emitted u64",
    ),
    ("genesis", &["genesis_nonce"], "Random nonce"),
    (
        "genesis",
        &["recovery_secret_step"],
        "Recovery verification map",
    ),
    (
        "genesis",
        &["recovery_secret_step", "commitment"],
        "Recovery-secret commitment, no plaintext",
    ),
    (
        "genesis",
        &["recovery_secret_step", "outcome"],
        "Closed ceremony outcome",
    ),
    ("enroll_device", &[], "operation map"),
    ("enroll_device", &["kind"], "operation discriminator"),
    ("enroll_device", &["device"], "Device verification scaffold"),
    ("enroll_device", &["device", "key"], "Verification key map"),
    (
        "enroll_device",
        &["device", "key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "enroll_device",
        &["device", "key", "public_key"],
        "Public verification bytes",
    ),
    (
        "enroll_device",
        &["device", "transport_key_binding"],
        "Transport public-key binding digest",
    ),
    (
        "enroll_device",
        &["device", "attestation"],
        "scaffold under the owner ruling",
    ),
    (
        "enroll_device",
        &["device", "attestation", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "enroll_device",
        &["device", "tier"],
        "Closed authority tier",
    ),
    (
        "enroll_device",
        &["device", "roles"],
        "Rule-selecting role bits, emitted u64",
    ),
    ("revoke_device", &[], "operation map"),
    ("revoke_device", &["kind"], "operation discriminator"),
    ("revoke_device", &["revoked_key"], "Verification key map"),
    (
        "revoke_device",
        &["revoked_key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "revoke_device",
        &["revoked_key", "public_key"],
        "Public verification bytes",
    ),
    ("rotate_key", &[], "operation map"),
    ("rotate_key", &["kind"], "operation discriminator"),
    (
        "rotate_key",
        &["new_device"],
        "Device verification scaffold",
    ),
    ("rotate_key", &["new_device", "key"], "Verification key map"),
    (
        "rotate_key",
        &["new_device", "key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "rotate_key",
        &["new_device", "key", "public_key"],
        "Public verification bytes",
    ),
    (
        "rotate_key",
        &["new_device", "transport_key_binding"],
        "Transport public-key binding digest",
    ),
    (
        "rotate_key",
        &["new_device", "attestation"],
        "scaffold under the owner ruling",
    ),
    (
        "rotate_key",
        &["new_device", "attestation", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "rotate_key",
        &["new_device", "tier"],
        "Closed authority tier",
    ),
    (
        "rotate_key",
        &["new_device", "roles"],
        "Rule-selecting role bits, emitted u64",
    ),
    ("rotate_key", &["old_key"], "Verification key map"),
    (
        "rotate_key",
        &["old_key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "rotate_key",
        &["old_key", "public_key"],
        "Public verification bytes",
    ),
    ("re_root", &[], "operation map"),
    ("re_root", &["kind"], "operation discriminator"),
    ("re_root", &["new_device"], "Device verification scaffold"),
    ("re_root", &["new_device", "key"], "Verification key map"),
    (
        "re_root",
        &["new_device", "key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "re_root",
        &["new_device", "key", "public_key"],
        "Public verification bytes",
    ),
    (
        "re_root",
        &["new_device", "transport_key_binding"],
        "Transport public-key binding digest",
    ),
    (
        "re_root",
        &["new_device", "attestation"],
        "scaffold under the owner ruling",
    ),
    (
        "re_root",
        &["new_device", "attestation", "kind"],
        "scaffold under the owner ruling",
    ),
    ("re_root", &["new_device", "tier"], "Closed authority tier"),
    (
        "re_root",
        &["new_device", "roles"],
        "Rule-selecting role bits, emitted u64",
    ),
    ("federation_confirm", &[], "operation map"),
    ("federation_confirm", &["kind"], "operation discriminator"),
    (
        "federation_confirm",
        &["confirm_kind"],
        "Closed confirmation rule",
    ),
    ("federation_confirm", &["confirm_id"], "Opaque confirm id"),
    (
        "federation_confirm",
        &["peer_vault_id"],
        "scaffold under the owner ruling",
    ),
    ("federation_confirm", &["epoch"], "Consent epoch"),
    ("federation_confirm", &["nonce"], "Random nonce"),
    ("critical_write_confirm", &[], "operation map"),
    (
        "critical_write_confirm",
        &["kind"],
        "operation discriminator",
    ),
    (
        "critical_write_confirm",
        &["schema_version"],
        "Schema discriminator",
    ),
    (
        "critical_write_confirm",
        &["confirm_id"],
        "Opaque confirm id",
    ),
    (
        "critical_write_confirm",
        &["gate_decision_id"],
        "Opaque gate decision id",
    ),
    ("critical_write_confirm", &["claim_id"], "Opaque claim id"),
    (
        "critical_write_confirm",
        &["effect_digest"],
        "Effect commitment",
    ),
    (
        "critical_write_confirm",
        &["read_frontier_hash"],
        "Frontier commitment",
    ),
    ("critical_write_confirm", &["nonce"], "Random nonce"),
    ("critical_write_confirm", &["expires_at"], "Timestamp"),
    ("critical_write_confirm", &["disposition"], "Closed rule"),
    (
        "critical_write_confirm",
        &["method"],
        "Closed verification method",
    ),
    ("federation_lifecycle", &[], "operation map"),
    ("federation_lifecycle", &["kind"], "operation discriminator"),
    (
        "federation_lifecycle",
        &["lifecycle_kind"],
        "Closed lifecycle rule",
    ),
    ("federation_lifecycle", &["pact_id"], "Opaque pact id"),
    ("federation_lifecycle", &["grant_ref"], "Opaque grant id"),
    (
        "federation_lifecycle",
        &["peer_vault_id"],
        "scaffold under the owner ruling",
    ),
    ("federation_lifecycle", &["pact_epoch"], "Pact epoch"),
    ("federation_lifecycle", &["pact_nonce"], "Nonce"),
    (
        "federation_lifecycle",
        &["pact_scope"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["scope_digest"],
        "Scope commitment",
    ),
    (
        "federation_lifecycle",
        &["gesture"],
        "Possession/consent signature",
    ),
    (
        "federation_lifecycle",
        &["successor_vault_id"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "schema_version"],
        "Fixed scope schema",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "worlds"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "worlds", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "worlds", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "worlds", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "facets"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "facets", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "facets", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "facets", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "bands"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "bands", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "bands", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "lo_to_hi", "bands", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "worlds"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "worlds", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "worlds", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "worlds", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "facets"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "facets", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "facets", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "facets", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "bands"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "bands", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "bands", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["pact_scope", "hi_to_lo", "bands", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "worlds"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "worlds", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "worlds", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "worlds", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "facets"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "facets", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "facets", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "facets", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "bands"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "bands", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "bands", "ids"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["effective_scope", "bands", "ids", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "federation_lifecycle",
        &["gesture", "signer"],
        "Verification key map",
    ),
    (
        "federation_lifecycle",
        &["gesture", "signer", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "federation_lifecycle",
        &["gesture", "signer", "public_key"],
        "Public verification bytes",
    ),
    (
        "federation_lifecycle",
        &["gesture", "signature"],
        "Pact consent signature",
    ),
    ("bind_actor", &[], "operation map"),
    ("bind_actor", &["kind"], "operation discriminator"),
    ("bind_actor", &["authority_key"], "Verification key map"),
    (
        "bind_actor",
        &["authority_key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "bind_actor",
        &["authority_key", "public_key"],
        "Public verification bytes",
    ),
    (
        "bind_actor",
        &["actor_ref"],
        "scaffold under the owner ruling",
    ),
    (
        "bind_actor",
        &["actor_class"],
        "Exact closed human/agent/system enum, despite String type",
    ),
    ("bind_actor", &["epoch"], "Binding epoch"),
    ("rebind_actor", &[], "operation map"),
    ("rebind_actor", &["kind"], "operation discriminator"),
    ("rebind_actor", &["authority_key"], "Verification key map"),
    (
        "rebind_actor",
        &["authority_key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "rebind_actor",
        &["authority_key", "public_key"],
        "Public verification bytes",
    ),
    (
        "rebind_actor",
        &["actor_ref"],
        "scaffold under the owner ruling",
    ),
    (
        "rebind_actor",
        &["actor_class"],
        "Exact closed human/agent/system enum, despite String type",
    ),
    ("rebind_actor", &["epoch"], "Binding epoch"),
    ("revoke_actor", &[], "operation map"),
    ("revoke_actor", &["kind"], "operation discriminator"),
    ("revoke_actor", &["authority_key"], "Verification key map"),
    (
        "revoke_actor",
        &["authority_key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "revoke_actor",
        &["authority_key", "public_key"],
        "Public verification bytes",
    ),
    ("revoke_actor", &["epoch"], "Revocation watermark"),
    ("machine_profile", &[], "operation map"),
    ("machine_profile", &["kind"], "operation discriminator"),
    ("machine_profile", &["machine"], "Opaque machine id"),
    (
        "machine_profile",
        &["owner"],
        "scaffold under the owner ruling",
    ),
    (
        "machine_profile",
        &["machine_key"],
        "Install public verification key",
    ),
    ("machine_profile", &["device_class"], "Closed machine class"),
    (
        "machine_profile",
        &["encryption_suite"],
        "Crypto-suite selector",
    ),
    (
        "machine_profile",
        &["encryption_key"],
        "Public encryption key",
    ),
    ("machine_profile", &["role"], "Closed machine role"),
    ("machine_profile", &["revision"], "Revision sequence"),
    ("machine_profile", &["machine_proof"], "Proof of possession"),
    (
        "machine_profile",
        &["seen_world_edits"],
        "OMITTED when empty",
    ),
    (
        "machine_profile",
        &["seen_world_edits", "*"],
        "Observed edit hash",
    ),
    ("machine_profile", &["carrier"], "Opaque carrier id"),
    (
        "machine_profile",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "machine_profile",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "machine_profile",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "machine_profile",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "machine_profile",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "machine_profile",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "machine_profile",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("machine_profile", &["act", "act"], "Closed action rule"),
    ("machine_profile", &["act", "target"], "Opaque target id"),
    ("machine_profile", &["act", "seen"], "Revision commitment"),
    ("machine_profile", &["act", "answer"], "Opaque answer id"),
    ("owner_root", &[], "operation map"),
    ("owner_root", &["kind"], "operation discriminator"),
    ("owner_root", &["owner"], "scaffold under the owner ruling"),
    ("owner_root", &["root"], "Recovery root id"),
    ("owner_root", &["recovery_suite"], "Crypto suite"),
    (
        "owner_root",
        &["recovery_key"],
        "Recovery public encryption key",
    ),
    ("owner_root", &["anchor_key"], "Anchor verification key"),
    ("world_privacy", &[], "operation map"),
    ("world_privacy", &["kind"], "operation discriminator"),
    ("world_privacy", &["act"], "scaffold under the owner ruling"),
    (
        "world_privacy",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "world_privacy",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "world_privacy",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    ("world_privacy", &["act", "grant"], "Opaque grant reference"),
    (
        "world_privacy",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "world_privacy",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("world_privacy", &["act", "act"], "Closed action rule"),
    ("world_privacy", &["act", "target"], "Opaque target id"),
    ("world_privacy", &["act", "seen"], "Revision commitment"),
    ("world_privacy", &["act", "answer"], "Opaque answer id"),
    ("world_privacy", &["world"], "Opaque world id"),
    ("world_privacy", &["machine"], "Opaque carrier id"),
    ("world_privacy", &["read"], "Closed read-location rule"),
    (
        "world_privacy",
        &["read_machine"],
        "Opaque designated machine id",
    ),
    ("world_privacy", &["sealed"], "Closed sealed-copy rule"),
    (
        "world_privacy",
        &["models"],
        "scaffold under the owner ruling",
    ),
    (
        "world_privacy",
        &["models", "*"],
        "scaffold under the owner ruling",
    ),
    ("world_key_wraps", &[], "operation map"),
    ("world_key_wraps", &["kind"], "operation discriminator"),
    ("world_key_wraps", &["world"], "Opaque world id"),
    ("world_key_wraps", &["generation"], "Key generation"),
    ("world_key_wraps", &["mint"], "Opaque key-mint id"),
    ("world_key_wraps", &["commitment"], "World-key commitment"),
    (
        "world_key_wraps",
        &["owner"],
        "scaffold under the owner ruling",
    ),
    ("world_key_wraps", &["policy"], "Policy revision commitment"),
    ("world_key_wraps", &["machine"], "Opaque signer/carrier id"),
    (
        "world_key_wraps",
        &["wraps"],
        "Array of recipient/encrypted-envelope pairs",
    ),
    ("world_key_wraps", &["wraps", "*"], "Two-element array"),
    (
        "world_key_wraps",
        &["wraps", "*", "*"],
        "crypto recipient id or sealed wrap",
    ),
    ("world_key_wraps", &["request"], "Request entry hash"),
    (
        "world_key_wraps",
        &["permitted"],
        "Opaque crypto-recipient identifiers",
    ),
    (
        "world_key_wraps",
        &["permitted", "*"],
        "Encoded cryptographic recipient identifier",
    ),
    ("owner_handover", &[], "operation map"),
    ("owner_handover", &["kind"], "operation discriminator"),
    (
        "owner_handover",
        &["shared_vault"],
        "scaffold under the owner ruling",
    ),
    ("owner_handover", &["cause"], "Closed lifecycle cause"),
    (
        "owner_handover",
        &["from"],
        "scaffold under the owner ruling",
    ),
    ("owner_handover", &["to"], "scaffold under the owner ruling"),
    (
        "owner_handover",
        &["from_keeps"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_handover",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_handover",
        &["proof"],
        "Validated lowercase BLAKE3 hex of proof, not identifying evidence",
    ),
    (
        "owner_handover",
        &["authorizer"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_handover",
        &["receipt"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_handover",
        &["affected_grants"],
        "Array always emitted, including empty",
    ),
    (
        "owner_handover",
        &["affected_grants", "*"],
        "Opaque grant id",
    ),
    (
        "owner_handover",
        &["retired_own_device_grants"],
        "Array always emitted, including empty",
    ),
    (
        "owner_handover",
        &["retired_own_device_grants", "*"],
        "Opaque grant id",
    ),
    ("residence_directive", &[], "operation map"),
    ("residence_directive", &["kind"], "operation discriminator"),
    ("residence_directive", &["id"], "Opaque directive id"),
    (
        "residence_directive",
        &["machine"],
        "Opaque target machine id",
    ),
    (
        "residence_directive",
        &["owner"],
        "scaffold under the owner ruling",
    ),
    ("residence_directive", &["issued_at"], "Timestamp"),
    ("residence_directive", &["act"], "Closed residence action"),
    (
        "residence_directive",
        &["window"],
        "scaffold under the owner ruling",
    ),
    ("residence_directive", &["item"], "Opaque item id"),
    ("residence_directive", &["before"], "Timestamp cutoff"),
    (
        "residence_directive",
        &["worlds"],
        "scaffold under the owner ruling",
    ),
    (
        "residence_directive",
        &["worlds", "*"],
        "scaffold under the owner ruling",
    ),
    ("residence_result", &[], "operation map"),
    ("residence_result", &["kind"], "operation discriminator"),
    ("residence_result", &["directive"], "Opaque directive id"),
    ("residence_result", &["machine"], "Opaque machine id"),
    (
        "residence_result",
        &["directive_entry"],
        "Parent directive hash",
    ),
    ("residence_result", &["finished_at"], "Timestamp"),
    ("residence_result", &["status"], "Closed result status"),
    ("residence_result", &["count"], "Count"),
    ("grant_travel", &[], "operation map"),
    ("grant_travel", &["kind"], "operation discriminator"),
    ("grant_travel", &["act"], "scaffold under the owner ruling"),
    (
        "grant_travel",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "grant_travel",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "grant_travel",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    ("grant_travel", &["act", "grant"], "Opaque grant reference"),
    (
        "grant_travel",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "grant_travel",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("grant_travel", &["act", "act"], "Closed action rule"),
    ("grant_travel", &["act", "target"], "Opaque target id"),
    ("grant_travel", &["act", "seen"], "Revision commitment"),
    ("grant_travel", &["act", "answer"], "Opaque answer id"),
    ("grant_travel", &["grant"], "Opaque grant id"),
    ("grant_travel", &["machine"], "Opaque carrier id"),
    (
        "grant_travel",
        &["choice"],
        "Closed BornWithField rule selection only, NOT actual prompt/why/keep text",
    ),
    (
        "grant_travel",
        &["choice", "*"],
        "Closed BornWithField enum",
    ),
    ("owner_work_request", &[], "operation map"),
    ("owner_work_request", &["kind"], "operation discriminator"),
    (
        "owner_work_request",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_work_request",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_work_request",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "owner_work_request",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_work_request",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "owner_work_request",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "owner_work_request",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("owner_work_request", &["act", "act"], "Closed action rule"),
    ("owner_work_request", &["act", "target"], "Opaque target id"),
    (
        "owner_work_request",
        &["act", "seen"],
        "Revision commitment",
    ),
    ("owner_work_request", &["act", "answer"], "Opaque answer id"),
    ("owner_work_request", &["carrier"], "Opaque install id"),
    ("owner_work_request", &["executor"], "Opaque install id"),
    ("owner_work_request", &["work"], "Closed work map"),
    (
        "owner_work_request",
        &["work", "kind"],
        "Closed work discriminator",
    ),
    (
        "owner_work_request",
        &["work", "mode"],
        "WorldKey only: closed key-work mode",
    ),
    (
        "owner_work_request",
        &["work", "change"],
        "Root or Custody only: closed change selector",
    ),
    (
        "owner_work_request",
        &["work", "root"],
        "Root only: crypto root id or nil, always key in Root",
    ),
    (
        "owner_work_request",
        &["work", "machine"],
        "Root only: opaque machine id or nil, always key in Root",
    ),
    (
        "owner_work_request",
        &["work", "home"],
        "PublishBundle only: opaque target install id",
    ),
    (
        "owner_work_request",
        &["work", "basis"],
        "Root only: verification basis map",
    ),
    (
        "owner_work_request",
        &["work", "basis", "roots"],
        "Always array, including empty",
    ),
    (
        "owner_work_request",
        &["work", "basis", "roots", "*"],
        "Crypto root id",
    ),
    (
        "owner_work_request",
        &["work", "basis", "roster"],
        "None -> nil, always key",
    ),
    (
        "owner_work_request",
        &["work", "basis", "roster_trusted"],
        "None -> nil, always key",
    ),
    (
        "owner_work_request",
        &["work", "basis", "anchored"],
        "Always array of pairs",
    ),
    (
        "owner_work_request",
        &["work", "basis", "anchored", "*"],
        "Two-element array",
    ),
    (
        "owner_work_request",
        &["work", "basis", "anchored", "*", "*"],
        "anchor key or entry hash",
    ),
    (
        "owner_work_request",
        &["work", "basis", "bound"],
        "OMITTED for None",
    ),
    (
        "owner_work_request",
        &["work", "basis", "parents"],
        "OMITTED when empty",
    ),
    (
        "owner_work_request",
        &["work", "basis", "parents", "*"],
        "Two-element pair",
    ),
    (
        "owner_work_request",
        &["work", "basis", "parents", "*", "*"],
        "entry hash or parent-hash array",
    ),
    (
        "owner_work_request",
        &["work", "basis", "parents", "*", "*", "*"],
        "Parent hash",
    ),
    (
        "owner_work_request",
        &["work", "generation"],
        "Custody or ExportSecret only: generation",
    ),
    (
        "owner_work_request",
        &["work", "input"],
        "Custody only: encrypted input digest",
    ),
    (
        "owner_work_request",
        &["work", "holder"],
        "Custody only: opaque install id",
    ),
    (
        "owner_work_request",
        &["work", "recipients"],
        "Custody only: inline permit array OR digest/count/pieces map",
    ),
    (
        "owner_work_request",
        &["work", "authority"],
        "Custody only: nil for install, root-id bytes for PinnedKit",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "*"],
        "Permit map",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "*", "machine"],
        "Opaque machine id / verification digest",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "*", "profile"],
        "Opaque machine id / verification digest",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "*", "encryption_key"],
        "Opaque machine id / verification digest",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "set"],
        "Piece-backed custody form only",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "count"],
        "Piece-backed custody form only",
    ),
    (
        "owner_work_request",
        &["work", "recipients", "pieces"],
        "Piece-backed custody form only",
    ),
    (
        "owner_work_request",
        &["work", "secret"],
        "ExportSecret only: opaque secret id, no secret name",
    ),
    (
        "owner_work_request",
        &["work", "export"],
        "ExportSecret only: opaque export id",
    ),
    (
        "owner_work_request",
        &["work", "digest"],
        "ExportSecret only: archive digest, None -> nil",
    ),
    (
        "owner_work_request",
        &["work", "export_act"],
        "ExportSecret only: signed export entry link, None -> nil",
    ),
    ("owner_work_request", &["work", "recipient"], "Permit map"),
    (
        "owner_work_request",
        &["work", "recipient", "machine"],
        "Opaque machine id / verification digest",
    ),
    (
        "owner_work_request",
        &["work", "recipient", "profile"],
        "Opaque machine id / verification digest",
    ),
    (
        "owner_work_request",
        &["work", "recipient", "encryption_key"],
        "Opaque machine id / verification digest",
    ),
    ("owner_work_request", &["privacy_basis"], "None -> nil"),
    (
        "owner_work_request",
        &["privacy_basis", "edit"],
        "Revision/entry commitment",
    ),
    (
        "owner_work_request",
        &["privacy_basis", "after"],
        "Revision/entry commitment",
    ),
    (
        "owner_work_request",
        &["privacy_basis", "key_owner"],
        "scaffold under the owner ruling",
    ),
    ("owner_work_result", &[], "operation map"),
    ("owner_work_result", &["kind"], "operation discriminator"),
    (
        "owner_work_result",
        &["request"],
        "Parent request entry hash",
    ),
    ("owner_work_result", &["executor"], "Opaque install id"),
    ("owner_work_result", &["outcome"], "Closed outcome map"),
    (
        "owner_work_result",
        &["outcome", "kind"],
        "Closed enacted/refused/sealed discriminator",
    ),
    (
        "owner_work_result",
        &["outcome", "reason"],
        "scaffold wire value or container",
    ),
    (
        "owner_work_result",
        &["outcome", "reason", "kind"],
        "Enacted-check only: closed checked/unchecked",
    ),
    (
        "owner_work_result",
        &["outcome", "reason", "reason"],
        "Enacted-check only: nil for checked",
    ),
    (
        "owner_work_result",
        &["outcome", "reason", "digest"],
        "Sealed only: encrypted-output digest/count",
    ),
    (
        "owner_work_result",
        &["outcome", "reason", "bytes"],
        "Sealed only: encrypted-output digest/count",
    ),
    (
        "owner_work_result",
        &["outcome", "reason", "envelopes"],
        "Sealed only: encrypted-output digest/count",
    ),
    ("owner_work_cancel", &[], "operation map"),
    ("owner_work_cancel", &["kind"], "operation discriminator"),
    (
        "owner_work_cancel",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_work_cancel",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_work_cancel",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "owner_work_cancel",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_work_cancel",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "owner_work_cancel",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "owner_work_cancel",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("owner_work_cancel", &["act", "act"], "Closed action rule"),
    ("owner_work_cancel", &["act", "target"], "Opaque target id"),
    ("owner_work_cancel", &["act", "seen"], "Revision commitment"),
    ("owner_work_cancel", &["act", "answer"], "Opaque answer id"),
    (
        "owner_work_cancel",
        &["carrier"],
        "Opaque carrier install id",
    ),
    ("owner_work_cancel", &["request"], "Request entry hash"),
    ("export_supplement_imported", &[], "operation map"),
    (
        "export_supplement_imported",
        &["kind"],
        "operation discriminator",
    ),
    (
        "export_supplement_imported",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "export_supplement_imported",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "export_supplement_imported",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "export_supplement_imported",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "export_supplement_imported",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "export_supplement_imported",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "export_supplement_imported",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    (
        "export_supplement_imported",
        &["act", "act"],
        "Closed action rule",
    ),
    (
        "export_supplement_imported",
        &["act", "target"],
        "Opaque target id",
    ),
    (
        "export_supplement_imported",
        &["act", "seen"],
        "Revision commitment",
    ),
    (
        "export_supplement_imported",
        &["act", "answer"],
        "Opaque answer id",
    ),
    (
        "export_supplement_imported",
        &["carrier"],
        "Opaque carrier install id",
    ),
    (
        "export_supplement_imported",
        &["request"],
        "Request entry hash",
    ),
    ("custody_permit_piece", &[], "operation map"),
    ("custody_permit_piece", &["kind"], "operation discriminator"),
    ("custody_permit_piece", &["carrier"], "Opaque install id"),
    (
        "custody_permit_piece",
        &["commitment"],
        "Permit-set digest/count map",
    ),
    (
        "custody_permit_piece",
        &["commitment", "set"],
        "Digest or sequence/count",
    ),
    (
        "custody_permit_piece",
        &["commitment", "count"],
        "Digest or sequence/count",
    ),
    (
        "custody_permit_piece",
        &["commitment", "pieces"],
        "Digest or sequence/count",
    ),
    (
        "custody_permit_piece",
        &["index"],
        "Piece ordinal / permit offset",
    ),
    (
        "custody_permit_piece",
        &["first"],
        "Piece ordinal / permit offset",
    ),
    (
        "custody_permit_piece",
        &["permits"],
        "Permit array always emitted",
    ),
    ("custody_permit_piece", &["permits", "*"], "Permit map"),
    (
        "custody_permit_piece",
        &["permits", "*", "machine"],
        "Opaque machine id / verification digest",
    ),
    (
        "custody_permit_piece",
        &["permits", "*", "profile"],
        "Opaque machine id / verification digest",
    ),
    (
        "custody_permit_piece",
        &["permits", "*", "encryption_key"],
        "Opaque machine id / verification digest",
    ),
    ("checkpoint_policy", &[], "operation map"),
    ("checkpoint_policy", &["kind"], "operation discriminator"),
    (
        "checkpoint_policy",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "checkpoint_policy",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "checkpoint_policy",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "checkpoint_policy",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "checkpoint_policy",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "checkpoint_policy",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "checkpoint_policy",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("checkpoint_policy", &["act", "act"], "Closed action rule"),
    ("checkpoint_policy", &["act", "target"], "Opaque target id"),
    ("checkpoint_policy", &["act", "seen"], "Revision commitment"),
    ("checkpoint_policy", &["act", "answer"], "Opaque answer id"),
    (
        "checkpoint_policy",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("checkpoint_policy", &["choice"], "None -> nil"),
    (
        "checkpoint_policy",
        &["choice", "roots"],
        "Verification root array",
    ),
    (
        "checkpoint_policy",
        &["choice", "roots", "*"],
        "Verification key map",
    ),
    (
        "checkpoint_policy",
        &["choice", "roots", "*", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "checkpoint_policy",
        &["choice", "roots", "*", "public_key"],
        "Public verification bytes",
    ),
    ("checkpoint_policy", &["choice", "quorum"], "Quorum rule"),
    (
        "checkpoint_policy",
        &["choice", "hardware"],
        "Hardware verification rule",
    ),
    ("home_node_pick", &[], "operation map"),
    ("home_node_pick", &["kind"], "operation discriminator"),
    (
        "home_node_pick",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "home_node_pick",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "home_node_pick",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "home_node_pick",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "home_node_pick",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "home_node_pick",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "home_node_pick",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("home_node_pick", &["act", "act"], "Closed action rule"),
    ("home_node_pick", &["act", "target"], "Opaque target id"),
    ("home_node_pick", &["act", "seen"], "Revision commitment"),
    ("home_node_pick", &["act", "answer"], "Opaque answer id"),
    (
        "home_node_pick",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("home_node_pick", &["node_id"], "Opaque node id"),
    ("conversation_training", &[], "operation map"),
    (
        "conversation_training",
        &["kind"],
        "operation discriminator",
    ),
    (
        "conversation_training",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "conversation_training",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "conversation_training",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "conversation_training",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training",
        &["act", "act"],
        "Closed action rule",
    ),
    (
        "conversation_training",
        &["act", "target"],
        "Opaque target id",
    ),
    (
        "conversation_training",
        &["act", "seen"],
        "Revision commitment",
    ),
    (
        "conversation_training",
        &["act", "answer"],
        "Opaque answer id",
    ),
    (
        "conversation_training",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    (
        "conversation_training",
        &["leave_out"],
        "Rule-selecting training flag",
    ),
    ("conversation_training_vault", &[], "operation map"),
    (
        "conversation_training_vault",
        &["kind"],
        "operation discriminator",
    ),
    (
        "conversation_training_vault",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training_vault",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training_vault",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "conversation_training_vault",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training_vault",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "conversation_training_vault",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "conversation_training_vault",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    (
        "conversation_training_vault",
        &["act", "act"],
        "Closed action rule",
    ),
    (
        "conversation_training_vault",
        &["act", "target"],
        "Opaque target id",
    ),
    (
        "conversation_training_vault",
        &["act", "seen"],
        "Revision commitment",
    ),
    (
        "conversation_training_vault",
        &["act", "answer"],
        "Opaque answer id",
    ),
    (
        "conversation_training_vault",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    (
        "conversation_training_vault",
        &["on"],
        "Rule-selecting training flag",
    ),
    (
        "conversation_training_vault",
        &["allow_opt_out"],
        "Rule-selecting training flag",
    ),
    ("home_candidacy", &[], "operation map"),
    ("home_candidacy", &["kind"], "operation discriminator"),
    ("home_candidacy", &["machine"], "Opaque machine id"),
    ("home_candidacy", &["node_id"], "Opaque node id"),
    (
        "home_candidacy",
        &["always_on"],
        "Rule-selecting candidacy flag",
    ),
    (
        "home_candidacy",
        &["primary"],
        "Rule-selecting candidacy flag",
    ),
    (
        "home_candidacy",
        &["macro_ready"],
        "Rule-selecting candidacy flag",
    ),
    (
        "home_candidacy",
        &["cloud"],
        "Rule-selecting candidacy flag",
    ),
    ("agent_grant_act", &[], "operation map"),
    ("agent_grant_act", &["kind"], "operation discriminator"),
    (
        "agent_grant_act",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "agent_grant_act",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "agent_grant_act",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "agent_grant_act",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("agent_grant_act", &["act", "act"], "Closed action rule"),
    ("agent_grant_act", &["act", "target"], "Opaque target id"),
    ("agent_grant_act", &["act", "seen"], "Revision commitment"),
    ("agent_grant_act", &["act", "answer"], "Opaque answer id"),
    (
        "agent_grant_act",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("agent_grant_act", &["grant"], "Opaque grant id"),
    (
        "agent_grant_act",
        &["member"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["expires_at"],
        "Mint expiry None -> nil",
    ),
    (
        "agent_grant_act",
        &["repo_bounds"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["verb_classes"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["verb_classes", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["grant_kind"],
        "Only GitPush writes this key",
    ),
    (
        "agent_grant_act",
        &["git_push_bounds"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["wallet_ref"],
        "scaffold under the owner ruling",
    ),
    ("agent_grant_act", &["role"], "OMITTED unless steward true"),
    (
        "agent_grant_act",
        &["working_view_bounds"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["acknowledged_topology"],
        "ONLY Revoke, REQUIRED there including empty array",
    ),
    (
        "agent_grant_act",
        &["acknowledged_topology", "*"],
        "Topology-token hash",
    ),
    (
        "agent_grant_act",
        &["scope"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "worlds"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "worlds", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "facets"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "facets", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "bands"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "bands", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "audience"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "audience", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "verbs"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "verbs", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["scope", "sensitivity"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["repo_bounds", "repo"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["repo_bounds", "project"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["git_push_bounds", "*"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["git_push_bounds", "*", "repo"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["git_push_bounds", "*", "project"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["working_view_bounds", "view"],
        "scaffold under the owner ruling",
    ),
    (
        "agent_grant_act",
        &["working_view_bounds", "account"],
        "scaffold under the owner ruling",
    ),
    ("policy_setting", &[], "operation map"),
    ("policy_setting", &["kind"], "operation discriminator"),
    (
        "policy_setting",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "policy_setting",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "policy_setting",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "policy_setting",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "policy_setting",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "policy_setting",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "policy_setting",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("policy_setting", &["act", "act"], "Closed action rule"),
    ("policy_setting", &["act", "target"], "Opaque target id"),
    ("policy_setting", &["act", "seen"], "Revision commitment"),
    ("policy_setting", &["act", "answer"], "Opaque answer id"),
    (
        "policy_setting",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("policy_setting", &["setting"], "Closed setting selector"),
    ("policy_setting", &["prior"], "Prior settings commitment"),
    ("policy_setting", &["value"], "Opaque value commitment"),
    ("export_act", &[], "operation map"),
    ("export_act", &["kind"], "operation discriminator"),
    ("export_act", &["act"], "scaffold under the owner ruling"),
    (
        "export_act",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    ("export_act", &["act", "by"], "Closed owner/agent selector"),
    (
        "export_act",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    ("export_act", &["act", "grant"], "Opaque grant reference"),
    ("export_act", &["act", "surface"], "Closed surface selector"),
    (
        "export_act",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("export_act", &["act", "act"], "Closed action rule"),
    ("export_act", &["act", "target"], "Opaque target id"),
    ("export_act", &["act", "seen"], "Revision commitment"),
    ("export_act", &["act", "answer"], "Opaque answer id"),
    (
        "export_act",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("export_act", &["export"], "Opaque export id"),
    ("export_act", &["format"], "scaffold under the owner ruling"),
    ("export_act", &["bytes"], "Byte count"),
    ("export_act", &["digest"], "Export archive digest"),
    ("owner_key_enroll", &[], "operation map"),
    ("owner_key_enroll", &["kind"], "operation discriminator"),
    (
        "owner_key_enroll",
        &["device"],
        "Device verification scaffold",
    ),
    (
        "owner_key_enroll",
        &["device", "key"],
        "Verification key map",
    ),
    (
        "owner_key_enroll",
        &["device", "key", "suite"],
        "Closed crypto-suite tag",
    ),
    (
        "owner_key_enroll",
        &["device", "key", "public_key"],
        "Public verification bytes",
    ),
    (
        "owner_key_enroll",
        &["device", "transport_key_binding"],
        "Transport public-key binding digest",
    ),
    (
        "owner_key_enroll",
        &["device", "attestation"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_key_enroll",
        &["device", "attestation", "kind"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_key_enroll",
        &["device", "tier"],
        "Closed authority tier",
    ),
    (
        "owner_key_enroll",
        &["device", "roles"],
        "Rule-selecting role bits, emitted u64",
    ),
    (
        "owner_key_enroll",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_key_enroll",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_key_enroll",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "owner_key_enroll",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "owner_key_enroll",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "owner_key_enroll",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "owner_key_enroll",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("owner_key_enroll", &["act", "act"], "Closed action rule"),
    ("owner_key_enroll", &["act", "target"], "Opaque target id"),
    ("owner_key_enroll", &["act", "seen"], "Revision commitment"),
    ("owner_key_enroll", &["act", "answer"], "Opaque answer id"),
    (
        "owner_key_enroll",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("owner_key_enroll", &["carrier"], "Opaque carrier id"),
    ("frontier_join", &[], "operation map"),
    ("frontier_join", &["kind"], "operation discriminator"),
    ("frontier_join", &["carrier"], "Opaque install id"),
    ("frontier_join", &["anchor"], "OMITTED except Anchor family"),
    (
        "frontier_join",
        &["side"],
        "OMITTED except AnchorSide scope",
    ),
    ("frontier_join", &["world"], "OMITTED except World scope"),
    ("origin_cut", &[], "operation map"),
    ("origin_cut", &["kind"], "operation discriminator"),
    ("origin_cut", &["act"], "scaffold under the owner ruling"),
    (
        "origin_cut",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    ("origin_cut", &["act", "by"], "Closed owner/agent selector"),
    (
        "origin_cut",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    ("origin_cut", &["act", "grant"], "Opaque grant reference"),
    ("origin_cut", &["act", "surface"], "Closed surface selector"),
    (
        "origin_cut",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("origin_cut", &["act", "act"], "Closed action rule"),
    ("origin_cut", &["act", "target"], "Opaque target id"),
    ("origin_cut", &["act", "seen"], "Revision commitment"),
    ("origin_cut", &["act", "answer"], "Opaque answer id"),
    (
        "origin_cut",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    (
        "origin_cut",
        &["repo"],
        "Opaque repo authority id/hash, not repository name",
    ),
    ("origin_cut", &["epoch"], "Origin epoch"),
    ("origin_cut", &["writer"], "Opaque machine id"),
    ("device_succession", &[], "operation map"),
    ("device_succession", &["kind"], "operation discriminator"),
    (
        "device_succession",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "device_succession",
        &["act", "owner"],
        "scaffold under the owner ruling",
    ),
    (
        "device_succession",
        &["act", "by"],
        "Closed owner/agent selector",
    ),
    (
        "device_succession",
        &["act", "agent"],
        "scaffold under the owner ruling",
    ),
    (
        "device_succession",
        &["act", "grant"],
        "Opaque grant reference",
    ),
    (
        "device_succession",
        &["act", "surface"],
        "Closed surface selector",
    ),
    (
        "device_succession",
        &["act", "surface_machine"],
        "scaffold under the owner ruling",
    ),
    ("device_succession", &["act", "act"], "Closed action rule"),
    ("device_succession", &["act", "target"], "Opaque target id"),
    ("device_succession", &["act", "seen"], "Revision commitment"),
    ("device_succession", &["act", "answer"], "Opaque answer id"),
    (
        "device_succession",
        &["machine"],
        "Opaque signer/carrier machine id",
    ),
    ("device_succession", &["client"], "Opaque client id"),
    (
        "device_succession",
        &["device_key"],
        "Public device verification key",
    ),
    (
        "device_succession",
        &["successor"],
        "Opaque successor install id",
    ),
    ("membership_execution", &[], "operation map"),
    ("membership_execution", &["kind"], "operation discriminator"),
    ("membership_execution", &["machine"], "Opaque carrier id"),
    (
        "membership_execution",
        &["shared_vault"],
        "scaffold under the owner ruling",
    ),
    ("membership_execution", &["cause"], "Closed execution rule"),
    (
        "membership_execution",
        &["person"],
        "scaffold under the owner ruling",
    ),
    (
        "membership_execution",
        &["member"],
        "scaffold under the owner ruling",
    ),
    (
        "membership_execution",
        &["act"],
        "scaffold under the owner ruling",
    ),
    (
        "membership_execution",
        &["receipt"],
        "scaffold under the owner ruling",
    ),
    ("membership_execution", &["executed_at"], "Timestamp"),
    (
        "membership_execution",
        &["withdrawn_grants"],
        "Array always emitted, including empty",
    ),
    (
        "membership_execution",
        &["withdrawn_grants", "*"],
        "Opaque grant id",
    ),
    (
        "membership_execution",
        &["handover"],
        "scaffold under the owner ruling",
    ),
    (
        "membership_execution",
        &["handover", "to"],
        "scaffold under the owner ruling",
    ),
    (
        "membership_execution",
        &["handover", "from_keeps"],
        "scaffold under the owner ruling",
    ),
    (
        "membership_execution",
        &["handover", "affected_grants"],
        "Array always emitted in handover map, including empty",
    ),
    (
        "membership_execution",
        &["handover", "affected_grants", "*"],
        "Opaque grant id",
    ),
    (
        "membership_execution",
        &["handover", "retired_own_device_grants"],
        "Array always emitted in handover map, including empty",
    ),
    (
        "membership_execution",
        &["handover", "retired_own_device_grants", "*"],
        "Opaque grant id",
    ),
];

fn sample_named(name: &str) -> AuthorityOp {
    every_op_sample()
        .into_iter()
        .find(|sample| op_kind_name(sample) == name)
        .expect("the sample table covers every op kind")
}

fn entry_for_op(op: AuthorityOp, overlay_seed: Option<[u8; 32]>) -> AuthorityLogEntry {
    let signing = SigningKey::from_bytes(&[7; 32]);
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some([9; 32]),
        seq: 2,
        parent_hashes: vec![[8; 32]],
        op,
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 150,
        overlay_seed,
    }
}

fn signed_entry(op: AuthorityOp, overlay_seed: Option<[u8; 32]>) -> AuthorityLogEntry {
    let mut entry = entry_for_op(op, overlay_seed);
    let transcript = authority_transcript(&entry).expect("the entry has a transcript");
    entry.signer.signature = SigningKey::from_bytes(&[7; 32])
        .sign(&transcript)
        .to_bytes()
        .to_vec();
    entry
}

fn slip_mint_with_named_bounds() -> AuthorityOp {
    let AuthorityOp::SlipMint(mut action) = sample_named("SlipMint") else {
        panic!("the SlipMint sample must be a mint");
    };
    action.renews = None;
    let claims = &mut action.claims;
    claims.parent_id = None;
    claims.binding_key = SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes();
    claims.single_use = false;
    claims.records = BTreeSet::from(["payroll-key".to_owned()]);
    claims.channels = BTreeSet::from(["git.receive-pack".to_owned()]);
    claims.org_ref = None;
    claims.grant_ref = None;
    claims.invitation_ref = None;
    claims.share_ref = None;
    claims.delegation = None;
    claims.trusted_contact = None;
    claims.seat_claim = None;
    AuthorityOp::SlipMint(action)
}

fn signed_slip_mint() -> AuthorityLogEntry {
    signed_entry(slip_mint_with_named_bounds(), Some([9; 32]))
}

fn value_at<'a>(mut value: &'a Value, path: &[&str]) -> &'a Value {
    for step in path {
        let Value::Map(entries) = value else {
            panic!("{path:?} traverses a non-map at {step}");
        };
        value = entries
            .iter()
            .find_map(|(key, child)| (key.as_str() == Some(*step)).then_some(child))
            .expect("the fixture emits the requested wire path");
    }
    value
}

fn wire_path_key(kind: &str, path: &[&str]) -> (String, Vec<String>) {
    (
        kind.to_owned(),
        path.iter().map(|step| (*step).to_owned()).collect(),
    )
}

fn collect_wire_paths(
    value: &Value,
    kind: &str,
    path: &mut Vec<String>,
    paths: &mut BTreeSet<Vec<String>>,
) {
    paths.insert(path.clone());
    if overlay_leaf_classes(kind).any(|class| {
        path.iter()
            .map(String::as_str)
            .eq(class.path.iter().copied())
    }) {
        return;
    }
    match value {
        Value::Map(entries) => {
            for (key, child) in entries {
                path.push(key.as_str().expect("op map keys are strings").to_owned());
                collect_wire_paths(child, kind, path, paths);
                path.pop();
            }
        }
        Value::Array(items) => {
            for child in items {
                path.push("*".to_owned());
                collect_wire_paths(child, kind, path, paths);
                path.pop();
            }
        }
        _ => {}
    }
}

#[test]
fn every_op_wire_path_is_classed() {
    let scaffold_paths: BTreeSet<_> = SCAFFOLD_PATHS
        .iter()
        .map(|(kind, path, _)| wire_path_key(kind, path))
        .collect();
    let overlay_paths: BTreeSet<_> = OVERLAY_LEAF_CLASSES
        .iter()
        .map(|class| wire_path_key(class.op_kind, class.path))
        .collect();
    let samples = every_op_sample();
    let sample_kinds: BTreeSet<_> = samples.iter().map(op_kind_name).collect();
    let expected_kinds: BTreeSet<_> = OP_KIND_NAMES.into_iter().collect();
    assert_eq!(sample_kinds, expected_kinds);
    let mut emitted = BTreeSet::new();
    for sample in samples {
        let op = op_value(&sample);
        let kind = value_at(&op, &["kind"])
            .as_str()
            .expect("the op kind is a string");
        let mut paths = BTreeSet::new();
        collect_wire_paths(&op, kind, &mut Vec::new(), &mut paths);
        for path in paths {
            let key = (kind.to_owned(), path);
            assert!(
                scaffold_paths.contains(&key) || overlay_paths.contains(&key),
                "unclassed op wire path: {key:?}",
            );
            emitted.insert(key);
        }
    }
    for (kind, path, reason) in SCAFFOLD_PATHS {
        assert!(
            emitted.contains(&wire_path_key(kind, path)),
            "dead scaffold row: {kind} {path:?} ({reason})",
        );
    }
    for class in OVERLAY_LEAF_CLASSES {
        assert!(
            emitted.contains(&wire_path_key(class.op_kind, class.path)),
            "dead overlay row: {} {:?}",
            class.op_kind,
            class.path,
        );
    }
}

#[test]
fn a_sealed_slip_mint_hides_its_records_and_opens_with_its_record() {
    let entry = signed_slip_mint();
    let bytes = encode_authority_log_entry_body(&entry).expect("a valid signed mint encodes");
    assert!(
        !bytes
            .windows(b"payroll-key".len())
            .any(|part| part == b"payroll-key"),
    );
    let unavailable =
        decode_authority_log_entry_body(&bytes).expect_err("the sealed mint needs its record");
    assert!(is_authority_overlay_unavailable(&unavailable));
    let record = authority_entry_overlay(&entry)
        .expect("the overlay record can be extracted")
        .expect("the named bounds produce an overlay");
    assert_eq!(record.leaves.len(), 2);
    assert_eq!(record.leaves[0].path, vec!["records".to_owned()]);
    assert_eq!(record.leaves[1].path, vec!["channels".to_owned()]);
    assert_eq!(
        open_authority_log_entry_body(&bytes, Some(&record))
            .expect("the matching record opens the mint"),
        entry,
    );
    assert_eq!(
        authority_entry_hash(&entry).expect("the entry has a hash"),
        *blake3::hash(&bytes).as_bytes(),
    );
    let record_bytes = encode_authority_overlay_record(&record).expect("the record encodes");
    let decoded_record =
        decode_authority_overlay_record(&record_bytes).expect("canonical record bytes decode");
    assert_eq!(decoded_record, record);
    assert_eq!(
        encode_authority_overlay_record(&decoded_record).expect("the decoded record re-encodes"),
        record_bytes,
    );
}

#[test]
fn a_wrong_seed_or_changed_leaf_does_not_open() {
    let entry = signed_slip_mint();
    let bytes = encode_authority_log_entry_body(&entry).expect("the signed mint encodes");
    let record = authority_entry_overlay(&entry)
        .expect("the record can be extracted")
        .expect("the mint has an overlay");
    let mut wrong_seed = record.clone();
    wrong_seed.seed = [10; 32];
    let mut changed_leaf = record.clone();
    changed_leaf.leaves[0].value = Value::Array(vec![Value::from("changed-payroll-key")]);
    let mut missing_leaf = record.clone();
    missing_leaf.leaves.remove(0);
    let mut extra_leaf = record.clone();
    extra_leaf.leaves.push(OverlayLeaf {
        path: vec!["unused".to_owned()],
        value: Value::from("extra"),
    });
    for (case, invalid_record) in [
        ("wrong seed", wrong_seed),
        ("changed leaf", changed_leaf),
        ("missing leaf", missing_leaf),
        ("extra leaf", extra_leaf),
    ] {
        let error = open_authority_log_entry_body(&bytes, Some(&invalid_record)).expect_err(case);
        assert!(
            !is_authority_overlay_unavailable(&error),
            "{case}: {error:?}"
        );
    }
    let unsealed = signed_entry(sample_named("SlipRevoke"), None);
    let unsealed_bytes =
        encode_authority_log_entry_body(&unsealed).expect("the unsealed revoke encodes");
    let error = open_authority_log_entry_body(&unsealed_bytes, Some(&record))
        .expect_err("an unsealed body refuses an overlay record");
    assert!(!is_authority_overlay_unavailable(&error));
}

#[test]
fn the_scaffold_verifies_without_its_record() {
    let entry = signed_slip_mint();
    let bytes = encode_authority_log_entry_body(&entry).expect("the signed mint encodes");
    let scaffold = verify_authority_log_entry_scaffold(&bytes)
        .expect("the signed scaffold verifies without its overlay record");
    assert!(scaffold.sealed);
    assert_eq!(
        scaffold.hash,
        authority_entry_hash(&entry).expect("the entry has a hash"),
    );
    assert_eq!(scaffold.op_kind, "slip_mint");
    assert_eq!(scaffold.signer, entry.signer);
    let signature_offset = bytes
        .windows(entry.signer.signature.len())
        .position(|part| part == entry.signer.signature.as_slice())
        .expect("the stored body contains its raw signature bytes");
    let mut tampered = bytes;
    tampered[signature_offset] ^= 1;
    assert!(verify_authority_log_entry_scaffold(&tampered).is_err());
    let unsealed = signed_entry(sample_named("SlipRevoke"), None);
    let unsealed_bytes =
        encode_authority_log_entry_body(&unsealed).expect("the signed revoke encodes");
    let unsealed_scaffold = verify_authority_log_entry_scaffold(&unsealed_bytes)
        .expect("an unsealed signed entry also verifies");
    assert!(!unsealed_scaffold.sealed);
}

#[test]
fn a_store_free_read_opens_a_plain_row_and_answers_a_sealed_rows_scaffold() {
    let mint = signed_slip_mint();
    let sealed_bytes = encode_authority_log_entry_body(&mint).expect("the signed mint encodes");
    let AuthorityEntryRead::Sealed(scaffold) =
        read_authority_log_entry_body(&sealed_bytes).expect("a sealed signed row reads")
    else {
        panic!("a sealed row must read as its scaffold");
    };
    assert!(scaffold.sealed);
    assert_eq!(scaffold.op_kind, "slip_mint");
    assert_eq!(
        scaffold.hash,
        authority_entry_hash(&mint).expect("the mint has a hash"),
    );
    let revoke = signed_entry(sample_named("SlipRevoke"), None);
    let plain_bytes = encode_authority_log_entry_body(&revoke).expect("the signed revoke encodes");
    assert_eq!(
        read_authority_log_entry_body(&plain_bytes).expect("a plain signed row reads"),
        AuthorityEntryRead::Open(revoke),
    );
    let signature_offset = sealed_bytes
        .windows(mint.signer.signature.len())
        .position(|part| part == mint.signer.signature.as_slice())
        .expect("the stored body contains its raw signature bytes");
    let mut tampered = sealed_bytes;
    tampered[signature_offset] ^= 1;
    assert!(read_authority_log_entry_body(&tampered).is_err());
}

#[test]
fn an_entry_with_no_overlay_leaf_encodes_as_before() {
    let mut checked = 0;
    for sample in every_op_sample() {
        let plain_op = op_value(&sample);
        if op_value_has_overlay_leaf(&plain_op) {
            continue;
        }
        let name = op_kind_name(&sample);
        // Samples describe wire shapes, not valid authorization requests.
        let entry = entry_for_op(sample, None);
        let encoded = entry_value(&entry, true);
        let encoded_op = value_at(&encoded, &["op"]);
        assert_eq!(encoded_op, &plain_op, "{name} changed an unsealed op");
        assert!(
            !contains_overlay_node(&encoded),
            "{name} has an overlay node",
        );
        checked += 1;
    }
    assert!(checked > 0, "the sample set must contain unsealed ops");
}

#[test]
fn the_seed_is_present_exactly_when_an_overlay_leaf_is() {
    let mut revoke = signed_entry(sample_named("SlipRevoke"), None);
    assert!(revoke.validate_shape().is_ok());
    revoke.overlay_seed = Some([9; 32]);
    assert!(revoke.validate_shape().is_err());
    let mut mint = signed_slip_mint();
    assert!(mint.validate_shape().is_ok());
    assert!(
        authority_overlay_seed_for(&mint.op)
            .expect("a present overlay leaf gets a seed")
            .is_some(),
    );
    mint.overlay_seed = None;
    assert!(mint.validate_shape().is_err());
    let AuthorityOp::SlipMint(mut empty_mint) = mint.op else {
        panic!("the fixture must be a mint");
    };
    empty_mint.claims.records.clear();
    empty_mint.claims.channels.clear();
    assert!(empty_mint.claims.delegation.is_none());
    assert!(empty_mint.claims.seat_claim.is_none());
    let empty_op = AuthorityOp::SlipMint(empty_mint);
    assert_eq!(
        authority_overlay_seed_for(&empty_op).expect("empty bounds need no seed"),
        None,
    );
    let AuthorityOp::OwnerKeyEnroll(mut enrollment) = sample_named("OwnerKeyEnroll") else {
        panic!("the enrollment sample must enroll an owner key");
    };
    enrollment.device.attestation.kind = OWNER_KEY_POSSESSION_KIND.to_owned();
    enrollment.device.attestation.evidence = vec![5; 64];
    let possession_op = AuthorityOp::OwnerKeyEnroll(enrollment);
    assert_eq!(
        authority_overlay_seed_for(&possession_op)
            .expect("owner-key possession evidence stays in the scaffold"),
        None,
    );
    let AuthorityOp::EnrollDevice { mut device } = sample_named("EnrollDevice") else {
        panic!("the device sample must enroll a device");
    };
    device.attestation.kind = "manufacturer-attestation/v1".to_owned();
    device.attestation.evidence = vec![3, 4];
    assert!(
        authority_overlay_seed_for(&AuthorityOp::EnrollDevice { device })
            .expect("identifying evidence gets a seed")
            .is_some(),
    );
}

#[test]
fn equal_values_commit_differently_by_path_and_seed() {
    let AuthorityOp::AgentGrantAct(mut grant) = sample_named("AgentGrantAct") else {
        panic!("the grant sample must be an agent grant act");
    };
    let AgentGrantChange::Mint { repo_bounds, .. } = &mut grant.change else {
        panic!("the first grant sample must mint a grant");
    };
    let bounds = repo_bounds
        .as_mut()
        .expect("the mint has repository bounds");
    bounds.readable = BTreeSet::from(["src/**".to_owned()]);
    bounds.editable = bounds.readable.clone();
    let op = op_value(&AuthorityOp::AgentGrantAct(grant));
    let readable = &["repo_bounds", "readable"];
    let editable = &["repo_bounds", "editable"];
    assert_eq!(value_at(&op, readable), value_at(&op, editable));
    let (first, _) = seal_op_value(&op, &[9; 32]);
    let (second, _) = seal_op_value(&op, &[10; 32]);
    for sealed in [&first, &second] {
        for path in [readable, editable] {
            assert!(matches!(
                value_at(sealed, path),
                Value::Ext(kind, commitment)
                    if *kind == AUTHORITY_OVERLAY_EXT_TYPE && commitment.len() == 32
            ));
        }
        assert_ne!(value_at(sealed, readable), value_at(sealed, editable));
    }
    assert_ne!(value_at(&first, readable), value_at(&second, readable));
    assert_ne!(value_at(&first, editable), value_at(&second, editable));
}

#[test]
fn a_sealed_row_verifies_as_structure_with_the_fields_its_signer_rule_reads() {
    let mint = signed_slip_mint();
    let bytes = encode_authority_log_entry_body(&mint).expect("the signed mint encodes");
    let row = verify_authority_public_row(&bytes)
        .expect("a sealed signed mint verifies without its overlay record");
    assert_eq!(row.standing(), &PublicStanding::SlipMint);
    assert_eq!(
        row.scaffold().hash,
        authority_entry_hash(&mint).expect("the mint has a hash"),
    );
    let structure = FoldRow::PassThrough(row);
    assert_eq!(
        structure.hash().expect("a pass-through row has its hash"),
        authority_entry_hash(&mint).expect("the mint has a hash"),
    );
    assert_eq!(structure.signer(), &mint.signer);
    assert_eq!(structure.cosigns(), mint.cosigns.as_slice());
    assert_eq!(structure.seq(), mint.seq);
    assert_eq!(structure.parent_hashes(), mint.parent_hashes.as_slice());
    assert_eq!(structure.vault_id(), mint.vault_id);
    assert!(structure.open().is_none());
    assert_eq!(FoldRow::Open(mint.clone()).open(), Some(&mint));

    let AuthorityOp::EnrollDevice { mut device } = sample_named("EnrollDevice") else {
        panic!("the device sample must enroll a device");
    };
    device.attestation.kind = "manufacturer-attestation/v1".to_owned();
    device.attestation.evidence = vec![3, 4];
    let op = AuthorityOp::EnrollDevice {
        device: device.clone(),
    };
    let seed = authority_overlay_seed_for(&op).expect("identifying evidence gets a seed");
    assert!(seed.is_some());
    let enroll = signed_entry(op, seed);
    let bytes = encode_authority_log_entry_body(&enroll).expect("the signed enrollment encodes");
    let row = verify_authority_public_row(&bytes)
        .expect("a sealed signed enrollment verifies without its overlay record");
    assert_eq!(
        row.standing(),
        &PublicStanding::EnrollDevice {
            key: device.key.clone(),
            tier: device.tier,
            roles: device.roles,
        },
    );
}

#[test]
fn a_row_with_nothing_sealed_or_a_broken_signature_is_not_structure() {
    let revoke = signed_entry(sample_named("SlipRevoke"), None);
    let plain = encode_authority_log_entry_body(&revoke).expect("the signed revoke encodes");
    assert!(
        verify_authority_public_row(&plain).is_err(),
        "a row with nothing sealed opens whole, it never passes through",
    );
    let mint = signed_slip_mint();
    let sealed = encode_authority_log_entry_body(&mint).expect("the signed mint encodes");
    let signature_offset = sealed
        .windows(mint.signer.signature.len())
        .position(|part| part == mint.signer.signature.as_slice())
        .expect("the stored body contains its raw signature bytes");
    let mut tampered = sealed;
    tampered[signature_offset] ^= 1;
    assert!(verify_authority_public_row(&tampered).is_err());
}

#[test]
fn a_commitment_node_sits_only_at_an_overlay_leaf_path_of_its_kind() {
    let node = Value::Ext(AUTHORITY_OVERLAY_EXT_TYPE, vec![1; 32]);
    let mint = |key: &str, value: Value| {
        Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_SLIP_MINT)),
            (Value::from(key), value),
        ])
    };
    assert!(commitments_sit_at_leaf_paths(
        &mint(SLIP_KEY_RECORDS, node.clone()),
        OP_KIND_SLIP_MINT,
    ));
    assert!(!commitments_sit_at_leaf_paths(
        &mint(
            SLIP_KEY_RECORDS,
            Value::Ext(AUTHORITY_OVERLAY_EXT_TYPE, vec![1; 31]),
        ),
        OP_KIND_SLIP_MINT,
    ));
    assert!(!commitments_sit_at_leaf_paths(
        &mint(SLIP_KEY_RECORDS, Value::Array(vec![node.clone()])),
        OP_KIND_SLIP_MINT,
    ));
    assert!(!commitments_sit_at_leaf_paths(
        &mint(SLIP_KEY_RECORDS, node.clone()),
        OP_KIND_SLIP_REVOKE,
    ));
    assert!(!commitments_sit_at_leaf_paths(
        &mint("binding_key", node.clone()),
        OP_KIND_SLIP_MINT,
    ));
    let enroll = |attestation_kind: &str| {
        Value::Map(vec![
            (Value::from(OP_KEY_KIND), Value::from(OP_KIND_ENROLL_DEVICE)),
            (
                Value::from("device"),
                Value::Map(vec![(
                    Value::from("attestation"),
                    Value::Map(vec![
                        (Value::from(KEY_ATTEST_KIND), Value::from(attestation_kind)),
                        (Value::from(KEY_ATTEST_EVIDENCE), node.clone()),
                    ]),
                )]),
            ),
        ])
    };
    assert!(commitments_sit_at_leaf_paths(
        &enroll("manufacturer-attestation/v1"),
        OP_KIND_ENROLL_DEVICE,
    ));
    assert!(
        !commitments_sit_at_leaf_paths(&enroll(HOST_ROOT_ATTESTATION_KIND), OP_KIND_ENROLL_DEVICE),
        "evidence of a kind that names nothing stays in the scaffold",
    );
}
