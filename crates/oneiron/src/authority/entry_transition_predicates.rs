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

/// A row that changes the roster: a genesis, an enrollment (an agent key or
/// an owner's own signing key), a revocation, a rotation or a re-root, the
/// ops whose `apply_op` arms write `FoldState::roster`. No arrival floor
/// refuses one (FIX [ARRIVAL-FLOOR-SIBLING-DIVERGENCE]), and one vouches for
/// every row of its own signer below it in its ancestry that a floor refuses
/// (`floor_refuses`, `sequence_ancestry`), so arrival order alone does not
/// change the roster, as a revocation's rule asks (ARCH-0040 ONE-REVOKE-D3).
/// A restriction it names keeps its floor and lands restriction only there.
/// Its signer's own order still binds it, on every install alike: a row at
/// or below a sequence its signer reached in the row's own ancestry is
/// refused (`fold_entry_state`, `state.seqs`). A parent of another signer
/// that this install's floor refuses still holds it back (FIX
/// [ROSTER-ROW-CROSS-SIGNER-FLOORED-PARENT]).
pub(super) fn changes_roster(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::Genesis { .. }
            | AuthorityOp::EnrollDevice { .. }
            | AuthorityOp::OwnerKeyEnroll(_)
            | AuthorityOp::RevokeDevice { .. }
            | AuthorityOp::RotateKey { .. }
            | AuthorityOp::ReRoot { .. }
    )
}

/// Whether this install's sequence floor refuses a row of `op` that reaches
/// it past the floor: every op but a roster change, which no floor refuses,
/// and a restriction, which lands restriction only.
pub(super) fn floor_refuses(op: &AuthorityOp) -> bool {
    !changes_roster(op) && !lands_restriction_only(op)
}

/// [`changes_roster`] for a stored row. A row that passes through is one by
/// its kind (a genesis, an enrollment, a rotation or a re-root), so no floor
/// refuses it on an install its record has not reached either: a sealed row
/// is judged as its open row is (census L5-22 1a-iii, RULING
/// PLAN-L5-22-ERASED-ROWS = A).
pub(super) fn row_changes_roster(row: &FoldRow) -> bool {
    match row {
        FoldRow::Open(entry) => changes_roster(&entry.op),
        FoldRow::PassThrough(row) => standing_changes_roster(row.standing()),
    }
}

/// [`floor_refuses`] for a stored row. No sealed kind lands restriction only,
/// so a floor refuses a row that passes through unless its kind changes the
/// roster.
pub(super) fn row_floor_refuses(row: &FoldRow) -> bool {
    match row {
        FoldRow::Open(entry) => floor_refuses(&entry.op),
        FoldRow::PassThrough(row) => !standing_changes_roster(row.standing()),
    }
}

/// Whether a row that passes through changes the roster by its kind, as
/// [`changes_roster`] says of its op.
pub(super) fn standing_changes_roster(standing: &PublicStanding) -> bool {
    matches!(
        standing,
        PublicStanding::Genesis { .. }
            | PublicStanding::EnrollDevice { .. }
            | PublicStanding::RotateKey { .. }
            | PublicStanding::ReRoot { .. }
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
