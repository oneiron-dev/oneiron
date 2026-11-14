//! The per-entry consent and retired-op predicates; `entry_transition` re-exports them.

use std::collections::BTreeSet;

use super::*;

/// A row a sequence floor refuses only to restriction (Astra #1430): a world
/// edit, a grant travel choice, a checkpoint policy choice, a home pick, a
/// person's conversation training choice, a setting's act, or a machine
/// revision. The roster rule reads each as a replica with no floor
/// does; this install never counts what it grants. A frontier join, which
/// grants nothing, lands so too, so such an act above it keeps its effect;
/// so does a custody permit piece, which has no effect alone (FIX 11866).
pub(super) fn lands_restriction_only(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::WorldPrivacy(_)
            | AuthorityOp::GrantTravelSet(_)
            | AuthorityOp::CheckpointPolicySet(_)
            | AuthorityOp::HomeNodePick(_)
            | AuthorityOp::OriginCut(_)
            | AuthorityOp::DeviceSuccession(_)
            | AuthorityOp::ConversationTrainingSet(_)
            | AuthorityOp::ConversationTrainingVaultSet(_)
            | AuthorityOp::PolicySettingSet(_)
            | AuthorityOp::MachineProfile(_)
            | AuthorityOp::FrontierJoin(_)
            | AuthorityOp::CustodyPermitPiece(_)
    )
}

/// A device-key op the host-rooted redesign retired (identity canon,
/// op-vocabulary amendment 2026-08-05): client enrollment is pairing-only,
/// and `RotateKey` became the re-root. An agent-only enrollment is not one of
/// them: it is the host enrolling an engine MACHINE writer (ARCH-0053 seeds
/// system actors through the authority registry at bootstrap), and an agent
/// key holds no consent, so it widens no authority.
pub(super) fn op_is_retired_device_op(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device } => device.roles != ROLE_AGENT,
        AuthorityOp::RotateKey { .. } => true,
        _ => false,
    }
}

/// Whether the vault door refuses `entry` as a retired device-key op. Only a
/// verified re-root's pre-handoff ancestry may still use one; the legacy
/// reference fold (no handoff set) keeps the historical rule.
pub(super) fn entry_is_retired(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    retired_outside_handoff(op_is_retired_device_op(&entry.op), hash, context)
}

/// [`op_is_retired_device_op`] for a stored row: a row that passes through
/// is one by its kind and its device's public roles, as its op would be.
pub(super) fn row_is_retired_device_op(row: &FoldRow) -> bool {
    match row {
        FoldRow::Open(entry) => op_is_retired_device_op(&entry.op),
        FoldRow::PassThrough(row) => standing_is_retired_device_op(row.standing()),
    }
}

fn standing_is_retired_device_op(standing: &PublicStanding) -> bool {
    match standing {
        PublicStanding::EnrollDevice { roles, .. } => *roles != ROLE_AGENT,
        PublicStanding::RotateKey { .. } => true,
        _ => false,
    }
}

/// Whether a stored row is a re-root, by its op or, when it passes through,
/// by its kind.
pub(super) fn row_is_re_root(row: &FoldRow) -> bool {
    match row {
        FoldRow::Open(entry) => matches!(entry.op, AuthorityOp::ReRoot { .. }),
        FoldRow::PassThrough(row) => matches!(row.standing(), PublicStanding::ReRoot { .. }),
    }
}

/// [`entry_is_retired`] for a stored row, under the same rule.
pub(super) fn row_is_retired(
    row: &FoldRow,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    retired_outside_handoff(row_is_retired_device_op(row), hash, context)
}

/// [`entry_is_retired`] for a row that passes through.
pub(super) fn public_row_is_retired(
    row: &AuthorityPublicRow,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    retired_outside_handoff(standing_is_retired_device_op(row.standing()), hash, context)
}

fn retired_outside_handoff(
    retired_op: bool,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    retired_op
        && context
            .pre_handoff_entries
            .is_some_and(|permitted| !permitted.contains(&hash))
}

pub(super) fn active_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    participant_keys(state, &entry.signer, &entry.cosigns).ok_or_else(|| {
        AuthorityFoldIssue::SignerNotInAncestry(authority_entry_hash(entry).unwrap_or([0; 32]))
    })
}

/// [`active_participant_keys`] for a row that passes through: its signer
/// and co-signers, each live with roles in its parent state.
pub(super) fn public_participant_keys(
    state: &FoldState,
    row: &AuthorityPublicRow,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let scaffold = row.scaffold();
    participant_keys(state, &scaffold.signer, &scaffold.cosigns)
        .ok_or(AuthorityFoldIssue::SignerNotInAncestry(scaffold.hash))
}

fn participant_keys(
    state: &FoldState,
    signer: &AuthoritySignature,
    cosigns: &[AuthoritySignature],
) -> Option<BTreeSet<AuthorityKey>> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(signer).chain(cosigns.iter()) {
        let key = &signature.public_key;
        if state
            .roster
            .get(key)
            .is_none_or(|device| device.revoked || device.roles == 0)
        {
            return None;
        }
        participants.insert(key.clone());
    }
    Some(participants)
}

pub(super) fn has_authority_consent(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) -> bool {
    participants.iter().any(|key| {
        state
            .roster
            .get(key)
            .is_some_and(|device| context.device_can_consent(device))
    })
}
