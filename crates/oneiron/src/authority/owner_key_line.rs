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
//! proving enrolments in its settled states and takes the new ones a key at
//! a time, earliest first: fewest ancestors, then hash ([`ProvingEnrolments`]).
//! When one's line changes the lines in force, the log folds again with the
//! lines of every enrolment taken so far ([`OwnerKeyLines`] in the context).
//! A line makes a row wait, be held or be refused. That can let another
//! enrolment fold (a held removal keeps its holder machine live), and it can
//! end one: where each of two branches enrolled the other's owner key as an
//! agent's before its own enrolment, each line refuses the other enrolment's
//! ancestry. Taken together, both would fall and leave lines no key answers;
//! a key at a time, the earlier one's line refuses the later one's ancestry
//! before the later one is taken, and the earlier one stands. Proving
//! enrolments of one key are taken together. The set only grows, and the
//! folds end when it stops: at most one more fold per enrolment in the log.
//! Only the log and its ancestry decide, so every replica judges the same
//! rows the same way. Two effects follow from the grow-only set. A row an
//! earlier fold refused, because it did not name a choice that a later fold
//! keeps waiting, can fold in the later one: it is judged against what
//! counts, as every row is. An enrolment taken in one fold that a later fold
//! ends keeps its line, which only adds waits. That holds for the enrolment
//! taken last too: a row its own line lets fold can prune its ancestry (a
//! sibling confirm reusing an ancestor confirm's nonce once a wait frees its
//! parent, Astra review OP-02, 16 Nov), or another line can refuse it. The
//! rows outside then wait for the owner's proof with no key yet to give it,
//! and the owner answers them with the next key it enrols. A line dropped
//! with its enrolment would let the rows that ended it stand outside it,
//! the dodge this row closes; a contending row that ends the enrolment with
//! no line in force leaves it no line, as it ends any other row.
//!
//! A fold past an adopted image leaves to the whole log every tail where the
//! covered log may hold a line, as its folds may then have been more than
//! one and the image keeps only the last, and every tail a line could reach
//! where the image's kept states do not show it
//! ([`tail_reaches_old_parents`]).

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The proving owner-key enrolments the folds of one log have taken so far,
/// each with the key it enrolled. It only grows.
#[derive(Debug, Default)]
pub(super) struct ProvingEnrolments(BTreeMap<AuthorityEntryHash, AuthorityKey>);

impl ProvingEnrolments {
    /// Takes the proving enrolments among `settled` (one fold's state after
    /// each entry once its handoffs settled) that the folds before it did
    /// not, a key at a time, earliest first, until one key's enrolments
    /// change the lines in force. The new lines when they changed: the log
    /// then folds again with them. None when no new enrolment changed them:
    /// the fold that gave `settled` used every line it needs.
    pub(super) fn grow(
        &mut self,
        settled: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
        in_force: Option<&OwnerKeyLines>,
    ) -> Option<OwnerKeyLines> {
        let mut found: Vec<(usize, AuthorityEntryHash, &AuthorityKey)> = settled
            .iter()
            .filter(|(hash, _)| !self.0.contains_key(*hash))
            .filter_map(|(hash, state)| {
                let Some(AuthorityOp::OwnerKeyEnroll(enrol)) =
                    entries.get(hash).map(|entry| &entry.op)
                else {
                    return None;
                };
                let key = &enrol.device.key;
                super::owner_proof::proves_for_the_owner(state, key).then(|| {
                    let depth = ancestors.get(hash).map_or(0, BTreeSet::len);
                    (depth, *hash, key)
                })
            })
            .collect();
        found.sort_unstable_by_key(|(depth, hash, _)| (*depth, *hash));
        while let Some(&(_, _, key)) = found.first() {
            found.retain(|(_, hash, enrolled)| {
                let same_key = *enrolled == key;
                if same_key {
                    self.0.insert(*hash, key.clone());
                }
                !same_key
            });
            let lines = self.lines(entries, ancestors);
            if lines.as_ref() != in_force {
                return lines;
            }
        }
        None
    }

    /// The lines of these enrolments over `entries`. None when no entry lies
    /// outside one: the log then needs no fold with lines.
    fn lines(
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
#[derive(Debug, Default, PartialEq, Eq)]
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

/// Whether a tail past an adopted image needs the whole log to judge it (row
/// CARRIER-PROOF-OLD-PARENTS):
///
/// - any tail, where a covered row a line reads (an owner choice, a carried
///   machine answer, an enrolment of the key a covered `OwnerKeyEnroll` row
///   enrols) lies outside that covered enrolment's line: the covered log may
///   have folded more than once, and a tail row can change what an earlier
///   fold took, where the image's admission keeps only the last fold's
///   settled rows (Astra review OP-01, 16 Nov: a tail confirm reusing the id
///   of a covered confirm that only an earlier fold counted pruned it and
///   the enrolment on it before any line existed). Where no covered row lies
///   outside a covered enrolment's line, and the tail passes the two checks
///   below, no line of the log with the tail holds a row that can count (a
///   tail row that names no parent lies outside every line, and its
///   transition refuses it for its ancestry wherever it lies; Astra review
///   OP-04, 16 Nov), so its folds judge as the image's admission does;
/// - an owner choice or a carried machine answer in the tail, where a
///   covered row a tail row names lies outside the line of a covered
///   `OwnerKeyEnroll` row (that row and its covered descendants). No kept
///   state decides it: a tail row folds on the merge of its parents, past
///   the tail rows between, where each parent's own proving key can be
///   revoked on another (Sol delta review DELTA-01, 16 Nov), and an
///   enrolment whose key a later row revoked still has its line;
/// - an enrolment in the tail of a key a covered `OwnerKeyEnroll` row that
///   did not fold valid enrolled. A valid one's key is on the merged roster,
///   where the tail admission already refuses its enrolment.
///
/// Every covered `OwnerKeyEnroll` row counts, valid or not, because the
/// whole log keeps the line of an enrolment any of its folds took. The guard
/// finds them in the covered bodies, never on the merged roster: a revoke of
/// a key its parents do not hold leaves that key a row with no role, and the
/// merge then strips the owner role a sibling enrolment gave it (Astra
/// review OP-03, 16 Nov). The image carries the body of every row a line
/// reads. It decodes the bodies of the covered rows that did not fold valid
/// for every tail, and every covered body only where either the covered
/// rows are not one chain (two rows of a chain are ordered, so none lies
/// outside another's line) or the tail holds a choice that names a covered
/// row other than a sole frontier row.
pub(super) fn tail_reaches_old_parents(
    image: &super::checkpoint_image::AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    CoveredLog {
        rows: &image.rows,
        frontier: &image.frontier,
        valid: &image.fold().valid_entries,
    }
    .tail_reaches_old_parents(tail)
}

/// [`tail_reaches_old_parents`] past an image of `covered`, folded under
/// `posture` with no pin and no peer, for the test door: the row summaries
/// such an image carries, its frontier and the rows its fold counts, each
/// as an image's build takes it.
#[cfg(oneiron_test_support)]
pub(crate) fn tail_reaches_old_parents_past_rows_for_test(
    covered: &[AuthorityLogEntry],
    tail: &[AuthorityLogEntry],
    posture: crate::HostingPrivacyPosture,
) -> crate::error::Result<bool> {
    let mut rows = BTreeMap::new();
    for entry in covered {
        let body = encode_authority_log_entry_body(entry)?;
        rows.insert(
            authority_entry_hash(entry)?,
            super::checkpoint_image::AuthorityCheckpointRow::of(entry, &body),
        );
    }
    let named: BTreeSet<AuthorityEntryHash> = covered
        .iter()
        .flat_map(|entry| entry.parent_hashes.iter().copied())
        .collect();
    let frontier: Vec<AuthorityEntryHash> = rows
        .keys()
        .filter(|hash| !named.contains(*hash))
        .copied()
        .collect();
    let capture =
        super::fold_resume::FoldCapture::for_checkpoint(frontier.iter().copied().collect());
    let (consent, local) = super::fold_engine::own_log_inputs(posture, None);
    let fold = super::fold_engine::fold_authority_log_inner(
        covered,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        consent,
        super::fold_engine::FoldLocalInputs {
            capture: Some(&capture),
            ..local
        },
    );
    fold.vault_id.ok_or_else(invalid_authority)?;
    let image = capture.take_image().ok_or_else(invalid_authority)?;
    let tail = tail
        .iter()
        .map(|entry| Ok((authority_entry_hash(entry)?, entry)))
        .collect::<crate::error::Result<BTreeMap<_, _>>>()?;
    Ok(CoveredLog {
        rows: &rows,
        frontier: &frontier,
        valid: &image.fold.valid_entries,
    }
    .tail_reaches_old_parents(&tail))
}

/// The covered rows of an adopted image, as [`tail_reaches_old_parents`]
/// reads them.
struct CoveredLog<'a> {
    /// Each covered row's summary, with the body of every row a line reads.
    rows: &'a BTreeMap<AuthorityEntryHash, super::checkpoint_image::AuthorityCheckpointRow>,
    /// The covered rows no covered row names.
    frontier: &'a [AuthorityEntryHash],
    /// The covered rows the image's fold counts.
    valid: &'a ValidEntries,
}

impl CoveredLog<'_> {
    /// [`tail_reaches_old_parents`] of these covered rows.
    fn tail_reaches_old_parents(
        &self,
        tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    ) -> bool {
        if tail.is_empty() {
            return false;
        }
        let rejected = self.owner_key_enrolments(|hash| !self.valid.contains(hash));
        if tail.values().any(|entry| {
            enrolled_key(&entry.op)
                .is_some_and(|key| rejected.values().any(|enrolled| enrolled == key))
        }) {
            return true;
        }
        let choices = tail
            .values()
            .any(|entry| needs_proof_off_the_line(&entry.op));
        let named: BTreeSet<&AuthorityEntryHash> = tail
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .filter(|parent| self.rows.contains_key(*parent))
            .collect();
        // A sole frontier row descends from every covered row, so it lies on
        // every covered enrolment's line.
        let sole_frontier = matches!(self.frontier, [only]
            if !named.is_empty() && named.iter().all(|parent| *parent == only));
        let chain = self.is_chain();
        if chain && (!choices || sole_frontier) {
            return false;
        }
        let mut enrolments = self.owner_key_enrolments(|hash| self.valid.contains(hash));
        enrolments.extend(rejected);
        if enrolments.is_empty() {
            return false;
        }
        let children = self.children();
        if !chain && self.holds_a_line(&enrolments, &children) {
            return true;
        }
        if !choices || sole_frontier {
            return false;
        }
        enrolments.keys().any(|enrolment| {
            let line = covered_line(&children, enrolment);
            named.is_empty() || named.iter().any(|parent| !line.contains(*parent))
        })
    }

    /// Whether a covered row a line reads lies outside the line of one of
    /// `enrolments` (the covered `OwnerKeyEnroll` rows, each with its key):
    /// an owner choice or a carried machine answer, or an enrolment of the
    /// same key other than that row. Here a line holds the enrolment's
    /// covered ancestors as well as its descendants, as a fold's line does.
    /// It reads every row any fold of the covered log could have taken, so
    /// where it finds none, no fold of the covered log held a line.
    fn holds_a_line(
        &self,
        enrolments: &BTreeMap<AuthorityEntryHash, AuthorityKey>,
        children: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    ) -> bool {
        if enrolments.is_empty() {
            return false;
        }
        let mut choices = Vec::new();
        let mut enrolled = Vec::new();
        for (hash, row) in self.rows {
            let Some(entry) = row
                .body
                .as_deref()
                .and_then(|body| decode_authority_log_entry_body(body).ok())
            else {
                continue;
            };
            if needs_proof_off_the_line(&entry.op) {
                choices.push(*hash);
            }
            if let Some(key) = enrolled_key(&entry.op) {
                enrolled.push((*hash, key.clone()));
            }
        }
        enrolments.iter().any(|(enrolment, key)| {
            let mut line = covered_line(children, enrolment);
            line.extend(self.ancestors(enrolment));
            choices.iter().any(|row| !line.contains(row))
                || enrolled
                    .iter()
                    .any(|(row, other)| other == key && row != enrolment && !line.contains(row))
        })
    }

    /// Every covered row `row` descends from.
    fn ancestors(&self, row: &AuthorityEntryHash) -> BTreeSet<AuthorityEntryHash> {
        let mut found = BTreeSet::new();
        let mut pending = vec![*row];
        while let Some(next) = pending.pop() {
            let Some(summary) = self.rows.get(&next) else {
                continue;
            };
            for parent in &summary.parents {
                if found.insert(*parent) {
                    pending.push(*parent);
                }
            }
        }
        found
    }

    /// Whether the covered rows form one chain: one frontier row, and no row
    /// names two parents. Every two rows of a chain are ordered.
    fn is_chain(&self) -> bool {
        self.frontier.len() == 1 && self.rows.values().all(|row| row.parents.len() <= 1)
    }

    /// The covered `OwnerKeyEnroll` rows that `pick` names, each with the key
    /// it enrols, read from the bodies the image carries.
    fn owner_key_enrolments(
        &self,
        pick: impl Fn(&AuthorityEntryHash) -> bool,
    ) -> BTreeMap<AuthorityEntryHash, AuthorityKey> {
        self.rows
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
    fn children(&self) -> BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> {
        let mut children: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (hash, row) in self.rows {
            for parent in &row.parents {
                children.entry(*parent).or_default().push(*hash);
            }
        }
        children
    }
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
