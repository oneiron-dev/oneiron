//! The owner key's line (row CARRIER-PROOF-OLD-PARENTS; Engine RULING 15 Nov
//! 21:09, design A, and OLDPARENTS-ENROL-DODGE = A, 22:05).
//!
//! An owner act that a carrier other than the owner's machine delivers waits
//! for the owner's proof where its parents hold a key that proves for the
//! owner ([`super::owner_proof`], item 2). A carrier that names parents from
//! before the first such key's enrolment is judged where no proving key
//! exists, and the act would then stand on every branch. So the fold reads
//! an owner key's enrolment across branches, as a handoff retires its
//! predecessor across branches. An entry that neither descends from a
//! proving enrolment nor lies beneath it is outside that enrolment's line,
//! and there:
//!
//! - an owner choice or a carried machine answer needs the proof: unproven
//!   and carried by a carrier that is not the owner's machine, the choice
//!   waits and the answer is held, as on parents that hold the key;
//! - an enrolment of the key that enrolment enrolled (any op, any role) is an
//!   invalid entry, so the roster merge cannot narrow the owner's key away.
//!
//! A proving enrolment is an `OwnerKeyEnroll` that folded and whose key
//! proves for the owner in the state it leaves. The first fold finds them.
//! When some entry lies outside one's line, the log folds again with
//! [`OwnerKeyLines`] in the context. Only the log and its ancestry decide,
//! so every replica judges the same rows the same way. The second fold takes
//! its lines from the first fold's enrolments: a line can only make a row
//! wait, be held or be refused, never count.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The entries a fold judges outside a proving owner-key enrolment's line.
#[derive(Debug, Default)]
pub(super) struct OwnerKeyLines {
    /// Owner choices and carried machine answers outside some proving
    /// enrolment's line: each needs the owner's proof.
    unproven_outside: BTreeSet<AuthorityEntryHash>,
    /// Enrolments, other than a proving one, of a key a proving enrolment
    /// enrolled, outside that enrolment's line: each is an invalid entry.
    refused_enrolments: BTreeSet<AuthorityEntryHash>,
}

impl OwnerKeyLines {
    /// The lines of the proving enrolments among `states`, the first fold's
    /// state after each entry. None when no entry lies outside one: the log
    /// then folds once, as before.
    pub(super) fn of(
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) -> Option<Self> {
        let enrolments: BTreeMap<AuthorityEntryHash, &AuthorityKey> = states
            .iter()
            .filter_map(|(hash, state)| {
                let AuthorityOp::OwnerKeyEnroll(enrol) = &entries.get(hash)?.op else {
                    return None;
                };
                super::owner_proof::proves_for_the_owner(state, &enrol.device.key)
                    .then_some((*hash, &enrol.device.key))
            })
            .collect();
        if enrolments.is_empty() {
            return None;
        }
        let beneath = |row: &AuthorityEntryHash, above: &AuthorityEntryHash| {
            ancestors.get(above).is_some_and(|line| line.contains(row))
        };
        let outside = |row: &AuthorityEntryHash, enrolment: &AuthorityEntryHash| {
            row != enrolment && !beneath(row, enrolment) && !beneath(enrolment, row)
        };
        let mut lines = Self::default();
        for (hash, entry) in entries {
            if needs_proof_off_the_line(&entry.op)
                && enrolments.keys().any(|enrolment| outside(hash, enrolment))
            {
                lines.unproven_outside.insert(*hash);
            }
            if let Some(key) = enrolled_key(&entry.op)
                && !enrolments.contains_key(hash)
                && enrolments
                    .iter()
                    .any(|(enrolment, enrolled)| *enrolled == key && outside(hash, enrolment))
            {
                lines.refused_enrolments.insert(*hash);
            }
        }
        (!lines.unproven_outside.is_empty() || !lines.refused_enrolments.is_empty())
            .then_some(lines)
    }

    /// Whether `hash` is an owner choice or a carried machine answer outside
    /// a proving enrolment's line: it needs the owner's proof there.
    pub(super) fn needs_proof(&self, hash: &AuthorityEntryHash) -> bool {
        self.unproven_outside.contains(hash)
    }

    /// Whether `hash` enrols an owner's key outside the line of the
    /// enrolment that made it the owner's: an invalid entry.
    pub(super) fn refuses(&self, hash: &AuthorityEntryHash) -> bool {
        self.refused_enrolments.contains(hash)
    }
}

/// Whether the op is one the two proof gates judge: the seven owner choice
/// kinds ([`super::owner_choice::owner_choice_landing`]) and a carried
/// machine answer ([`super::machine_profile::apply_owner_answer`]).
fn needs_proof_off_the_line(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::CheckpointPolicySet(_)
        | AuthorityOp::HomeNodePick(_)
        | AuthorityOp::OriginCut(_)
        | AuthorityOp::DeviceSuccession(_)
        | AuthorityOp::ConversationTrainingSet(_)
        | AuthorityOp::ConversationTrainingVaultSet(_)
        | AuthorityOp::PolicySettingSet(_) => true,
        AuthorityOp::MachineProfile(profile) => profile.act.is_some(),
        _ => false,
    }
}

/// The key an enrolment op puts on the roster.
fn enrolled_key(op: &AuthorityOp) -> Option<&AuthorityKey> {
    match op {
        AuthorityOp::EnrollDevice { device } => Some(&device.key),
        AuthorityOp::OwnerKeyEnroll(enrol) => Some(&enrol.device.key),
        _ => None,
    }
}

/// Whether a tail row past an adopted image could be judged on a covered
/// parent that holds no key proving for the owner while the image's merged
/// state holds one: a carrier's old parents, which only the whole log judges
/// (row CARRIER-PROOF-OLD-PARENTS). True only for a tail with an owner
/// choice in it (the only kind of these two gates that folds past an image)
/// and a covered parent whose kept state the image's owner key does not
/// reach.
pub(super) fn tail_reaches_old_parents(
    image: &super::checkpoint_image::AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    if !tail
        .values()
        .any(|entry| needs_proof_off_the_line(&entry.op))
        || !super::owner_proof::not_mine_carriers_need_proof(&image.aggregate.merged)
    {
        return false;
    }
    tail.values()
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter(|parent| image.rows.contains_key(*parent))
        .any(|parent| {
            !image
                .state_at(parent)
                .flatten()
                .is_some_and(|state| super::owner_proof::not_mine_carriers_need_proof(&state))
        })
}
