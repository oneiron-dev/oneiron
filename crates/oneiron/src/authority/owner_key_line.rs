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
//!   Another proving enrolment of the same key is not refused: its shape is
//!   fixed and its possession proof names its holder machine, so both
//!   branches hold the same roster row and the merge keeps it. Refusing
//!   both would let a host that replays the owner's proof on a sibling row
//!   end the owner's own enrolment.
//!
//! A proving enrolment is an `OwnerKeyEnroll` that stands once the handoffs
//! settle and whose key proves for the owner in the state it leaves. An
//! enrolment a handoff prunes is none: its line would make the new root's
//! acts wait where no key could prove them. Each fold of the log finds the
//! proving enrolments in its settled states ([`ProvingEnrolments`]). While a
//! fold finds one the folds before it did not, and some entry lies outside
//! one's line, the log folds again with the lines of every proving enrolment
//! found so far ([`OwnerKeyLines`] in the context). A line makes a row wait,
//! be held or be refused, and that can let another enrolment fold (a held
//! removal keeps its holder machine live), so the set only grows, and the
//! folds end when it stops: at most one more fold per enrolment in the log.
//! Only the log and its ancestry decide, so every replica judges the same
//! rows the same way. Two effects follow from the grow-only set. A row an
//! earlier fold refused, because it did not name a choice that a later fold
//! keeps waiting, can fold in the later one: it is judged against what
//! counts, as every row is. An enrolment one fold found and a later fold
//! refuses (it descends from a refused enrolment) keeps its line, which can
//! only add waits.
//!
//! A fold past an adopted image leaves to the whole log every tail a line
//! could reach where the image's kept states do not show it
//! ([`tail_reaches_old_parents`]).

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The proving owner-key enrolments the folds of one log have found so far,
/// each with the key it enrolled. It only grows.
#[derive(Debug, Default)]
pub(super) struct ProvingEnrolments(BTreeMap<AuthorityEntryHash, AuthorityKey>);

impl ProvingEnrolments {
    /// Adds the proving enrolments among `settled`, one fold's state after
    /// each entry once its handoffs settled. Whether any of them is new.
    pub(super) fn add_found(
        &mut self,
        settled: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ) -> bool {
        let before = self.0.len();
        for (hash, state) in settled {
            let Some(AuthorityOp::OwnerKeyEnroll(enrol)) = entries.get(hash).map(|entry| &entry.op)
            else {
                continue;
            };
            if super::owner_proof::proves_for_the_owner(state, &enrol.device.key) {
                self.0
                    .entry(*hash)
                    .or_insert_with(|| enrol.device.key.clone());
            }
        }
        self.0.len() > before
    }

    /// The lines of these enrolments over `entries`. None when no entry lies
    /// outside one: the log then needs no fold with lines.
    pub(super) fn lines(
        &self,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) -> Option<OwnerKeyLines> {
        if self.0.is_empty() {
            return None;
        }
        let beneath = |row: &AuthorityEntryHash, above: &AuthorityEntryHash| {
            ancestors.get(above).is_some_and(|line| line.contains(row))
        };
        let outside = |row: &AuthorityEntryHash, enrolment: &AuthorityEntryHash| {
            row != enrolment && !beneath(row, enrolment) && !beneath(enrolment, row)
        };
        let mut lines = OwnerKeyLines::default();
        for (hash, entry) in entries {
            if needs_proof_off_the_line(&entry.op)
                && self.0.keys().any(|enrolment| outside(hash, enrolment))
            {
                lines.unproven_outside.insert(*hash);
            }
            if let Some(key) = enrolled_key(&entry.op)
                && !self.0.contains_key(hash)
                && self
                    .0
                    .iter()
                    .any(|(enrolment, enrolled)| enrolled == key && outside(hash, enrolment))
            {
                lines.refused_enrolments.insert(*hash);
            }
        }
        (!lines.unproven_outside.is_empty() || !lines.refused_enrolments.is_empty())
            .then_some(lines)
    }
}

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

/// Whether a tail past an adopted image holds a row an owner key's line
/// could reach where the image's kept states do not show it, which only the
/// whole log judges (row CARRIER-PROOF-OLD-PARENTS):
///
/// - an owner choice or a carried machine answer in the tail, and a tail
///   row's covered parent outside the line of a covered `OwnerKeyEnroll` row
///   (that row and its covered descendants) whose kept state holds no key
///   proving for the owner. The image's merged state cannot tell: an
///   enrolment whose key a later row revoked still has its line;
/// - an enrolment in the tail of a key a covered `OwnerKeyEnroll` row that
///   did not fold valid enrolled. A valid one's key is on the merged roster,
///   where the tail admission already refuses its enrolment.
///
/// Every covered `OwnerKeyEnroll` row counts, valid or not, because the
/// whole log keeps the line of an enrolment any of its folds found. The
/// image carries the body of every enrolment row. It decodes the bodies of
/// the covered rows that did not fold valid when the tail holds a choice or
/// an enrolment, and every covered body only when a tail row's covered
/// parent is bare and the vault may have had a proving enrolment.
pub(super) fn tail_reaches_old_parents(
    image: &super::checkpoint_image::AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    let choices = tail
        .values()
        .any(|entry| needs_proof_off_the_line(&entry.op));
    let enrols = tail.values().any(|entry| enrolled_key(&entry.op).is_some());
    if !choices && !enrols {
        return false;
    }
    let valid = &image.fold().valid_entries;
    let rejected = covered_owner_key_enrolments(image, |hash| !valid.contains(hash));
    if tail.values().any(|entry| {
        enrolled_key(&entry.op).is_some_and(|key| rejected.values().any(|enrolled| enrolled == key))
    }) {
        return true;
    }
    if !choices {
        return false;
    }
    let bare: BTreeSet<&AuthorityEntryHash> = tail
        .values()
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter(|parent| image.rows.contains_key(*parent))
        .filter(|parent| {
            !image
                .state_at(parent)
                .flatten()
                .is_some_and(|state| super::owner_proof::not_mine_carriers_need_proof(&state))
        })
        .collect();
    // A valid enrolment leaves its key on the merged roster with its owner
    // role, revoked or not.
    let merged = &image.aggregate.merged;
    let owner_key_ever = merged.roster.iter().any(|(key, device)| {
        device.roles & ROLE_OWNER != 0
            && !(merged.hosted && super::machine_profile::in_host_custody(merged, key))
    });
    if bare.is_empty() || (rejected.is_empty() && !owner_key_ever) {
        return false;
    }
    let mut enrolments = covered_owner_key_enrolments(image, |hash| valid.contains(hash));
    enrolments.extend(rejected);
    let children = covered_children(image);
    enrolments.keys().any(|enrolment| {
        let line = covered_line(&children, enrolment);
        bare.iter().any(|parent| !line.contains(*parent))
    })
}

/// The covered `OwnerKeyEnroll` rows of `image` that `pick` names, each
/// with the key it enrols, read from the bodies the image carries.
fn covered_owner_key_enrolments(
    image: &super::checkpoint_image::AuthorityCheckpointV2,
    pick: impl Fn(&AuthorityEntryHash) -> bool,
) -> BTreeMap<AuthorityEntryHash, AuthorityKey> {
    image
        .rows
        .iter()
        .filter_map(|(hash, row)| {
            if !pick(hash) {
                return None;
            }
            let entry = decode_authority_log_entry_body(row.body.as_deref()?).ok()?;
            let AuthorityOp::OwnerKeyEnroll(enrol) = entry.op else {
                return None;
            };
            Some((*hash, enrol.device.key))
        })
        .collect()
}

/// Each covered row's covered children.
fn covered_children(
    image: &super::checkpoint_image::AuthorityCheckpointV2,
) -> BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> {
    let mut children: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (hash, row) in &image.rows {
        for parent in &row.parents {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    children
}

/// `enrolment` and every covered row that descends from it.
fn covered_line(
    children: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    enrolment: &AuthorityEntryHash,
) -> BTreeSet<AuthorityEntryHash> {
    let mut line = BTreeSet::from([*enrolment]);
    let mut pending = vec![*enrolment];
    while let Some(next) = pending.pop() {
        for child in children.get(&next).into_iter().flatten() {
            if line.insert(*child) {
                pending.push(*child);
            }
        }
    }
    line
}
