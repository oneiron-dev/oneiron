//! The per-entry consent and retired-op predicates; `entry_transition` re-exports them.

use std::collections::BTreeSet;

use super::*;

/// A row a sequence floor refuses only to restriction (Astra #1430): a world
/// edit, a grant travel choice, a checkpoint policy choice, a home pick, a
/// person's conversation training choice, or a machine revision. The roster rule reads each as a replica with no floor
/// does; this install never counts what it grants. A frontier join, which
/// grants nothing, lands so too, so such an act above it keeps its effect.
pub(super) fn lands_restriction_only(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::WorldPrivacy(_)
            | AuthorityOp::GrantTravelSet(_)
            | AuthorityOp::CheckpointPolicySet(_)
            | AuthorityOp::HomeNodePick(_)
            | AuthorityOp::ConversationTrainingSet(_)
            | AuthorityOp::ConversationTrainingVaultSet(_)
            | AuthorityOp::MachineProfile(_)
            | AuthorityOp::FrontierJoin(_)
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
    op_is_retired_device_op(&entry.op)
        && context
            .pre_handoff_entries
            .is_some_and(|permitted| !permitted.contains(&hash))
}

pub(super) fn active_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        if state
            .roster
            .get(key)
            .is_none_or(|device| device.revoked || device.roles == 0)
        {
            return Err(AuthorityFoldIssue::SignerNotInAncestry(
                authority_entry_hash(entry).unwrap_or([0; 32]),
            ));
        }
        participants.insert(key.clone());
    }
    Ok(participants)
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
