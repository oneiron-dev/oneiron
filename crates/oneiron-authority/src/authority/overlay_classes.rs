//! Which op leaves of an AUTHORITY_LOG entry are overlay (census L5-22).
//!
//! RULING L5-22-OVERLAY-SCOPE = A: the overlay takes every value a person
//! typed or chose (slip records and channels, a support purpose and ticket
//! ref, repo-grant ref names and globs, refusal and result reasons, the seat
//! lease owner, identifying attestation evidence). Opaque ids that record who
//! acted stay in the scaffold: once their person is erased they resolve to
//! nothing. Every other op leaf is scaffold: ids, keys, digests, times,
//! counters, closed rule tags, verb and model names.
//!
//! A leaf is named by its wire path: the map keys from the op map's root. An
//! array leaf is taken whole, so its length is sealed with its values.

use super::*;

/// One overlay leaf of one op kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayLeafClass {
    /// The op map's `kind` this row applies to.
    pub op_kind: &'static str,
    /// The leaf's wire path: map keys from the op map's root.
    pub path: &'static [&'static str],
    /// A sibling key and the values of it that keep the leaf in the
    /// scaffold: the leaf names nothing when the sibling says so.
    pub scaffold_when_sibling: Option<(&'static str, &'static [&'static str])>,
    /// Why the leaf names something.
    pub reason: &'static str,
}

const fn leaf(
    op_kind: &'static str,
    path: &'static [&'static str],
    reason: &'static str,
) -> OverlayLeafClass {
    OverlayLeafClass {
        op_kind,
        path,
        scaffold_when_sibling: None,
        reason,
    }
}

/// The attestation kind of a host's root key (`oneiron::authority::slip_vault`):
/// a software key, its evidence names no device.
pub const HOST_ROOT_ATTESTATION_KIND: &str = "HostRoot";

/// The attestation kind of a passphrase-derived software key: its evidence
/// names no device.
pub const SOFTWARE_ARGON2ID_ATTESTATION_KIND: &str = "SoftwareArgon2id";

/// The attestation kinds whose evidence names nothing (RULING
/// L5-22-OVERLAY-SCOPE = A takes identifying evidence only): an owner-key
/// possession proof is a signature over the enrollment challenge,
/// verification material (owner_key_enrollment.rs); the two software kinds
/// attest no device.
pub const NON_IDENTIFYING_ATTESTATION_KINDS: &[&str] = &[
    OWNER_KEY_POSSESSION_KIND,
    HOST_ROOT_ATTESTATION_KIND,
    SOFTWARE_ARGON2ID_ATTESTATION_KIND,
];

/// Attestation evidence names the device or its maker, except evidence of a
/// [`NON_IDENTIFYING_ATTESTATION_KINDS`] kind.
const fn attestation_evidence(
    op_kind: &'static str,
    path: &'static [&'static str],
) -> OverlayLeafClass {
    OverlayLeafClass {
        op_kind,
        path,
        scaffold_when_sibling: Some((KEY_ATTEST_KIND, NON_IDENTIFYING_ATTESTATION_KINDS)),
        reason: "identifying attestation evidence",
    }
}

/// Every overlay leaf, by op kind. A leaf not listed here is scaffold.
pub const OVERLAY_LEAF_CLASSES: &[OverlayLeafClass] = &[
    leaf(
        OP_KIND_SLIP_MINT,
        &[SLIP_KEY_RECORDS],
        "the secrets and repositories a slip may use, by name",
    ),
    leaf(
        OP_KIND_SLIP_MINT,
        &[SLIP_KEY_CHANNELS],
        "the door channels a slip may use, by name",
    ),
    leaf(
        OP_KIND_SLIP_MINT,
        &[SLIP_KEY_DELEGATION, DELEGATION_KEY_PURPOSE],
        "the support purpose the customer wrote",
    ),
    leaf(
        OP_KIND_SLIP_MINT,
        &[SLIP_KEY_DELEGATION, DELEGATION_KEY_TICKET_REF],
        "the support ticket the customer named",
    ),
    leaf(
        OP_KIND_SLIP_MINT,
        &[SLIP_KEY_SEAT_CLAIM, SEAT_CLAIM_KEY_LEASE_OWNER],
        "the seat lease owner (RULING L5-22-OVERLAY-SCOPE)",
    ),
    attestation_evidence(
        OP_KIND_GENESIS,
        &["device", "attestation", KEY_ATTEST_EVIDENCE],
    ),
    attestation_evidence(
        OP_KIND_ENROLL_DEVICE,
        &["device", "attestation", KEY_ATTEST_EVIDENCE],
    ),
    attestation_evidence(
        OP_KIND_ROTATE_KEY,
        &["new_device", "attestation", KEY_ATTEST_EVIDENCE],
    ),
    attestation_evidence(
        OP_KIND_RE_ROOT,
        &["new_device", "attestation", KEY_ATTEST_EVIDENCE],
    ),
    attestation_evidence(
        OP_KIND_OWNER_KEY_ENROLL,
        &["device", "attestation", KEY_ATTEST_EVIDENCE],
    ),
    leaf(
        OP_KIND_AGENT_GRANT_ACT,
        &["repo_bounds", "refs"],
        "the git refs a repo grant names",
    ),
    leaf(
        OP_KIND_AGENT_GRANT_ACT,
        &["repo_bounds", "readable"],
        "the path globs a repo grant may read",
    ),
    leaf(
        OP_KIND_AGENT_GRANT_ACT,
        &["repo_bounds", "editable"],
        "the path globs a repo grant may edit",
    ),
    leaf(
        OP_KIND_AGENT_GRANT_ACT,
        &["wallet_ref", "issuer"],
        "the wallet's issuer, an outside account (as a support ticket ref)",
    ),
    leaf(
        OP_KIND_AGENT_GRANT_ACT,
        &["wallet_ref", "id"],
        "the wallet's account at its issuer (as a support ticket ref)",
    ),
    leaf(
        OP_KIND_RESIDENCE_RESULT,
        &["reason"],
        "the refusal reason a machine wrote",
    ),
    leaf(
        OP_KIND_OWNER_WORK_RESULT,
        &["outcome", "reason", "refs"],
        "the custody manifest refs a result names",
    ),
];

/// The overlay leaves of op kind `op_kind`, in table order.
pub fn overlay_leaf_classes(op_kind: &str) -> impl Iterator<Item = &'static OverlayLeafClass> {
    OVERLAY_LEAF_CLASSES
        .iter()
        .filter(move |class| class.op_kind == op_kind)
}
