//! The Coach's unclear-note clustering (ARCH-0056 §5 #unclear, FIX 7824):
//! the recurring `no_label_fits` notes the attribution judge left become a
//! proposed new label in the owner's run tray.
//!
//! The substrate is deterministic and owns the state; the policy is the
//! model's. A pass walks the unclear ledger in key order from its cursor.
//! Each `no_label_fits` note with words, within its scope (lane, consent scope
//! and project), is put to the host's ladder once per fingerprint as one typed
//! Choice: does it describe the same missing label as one of the scope's
//! patterns, a new one, or none? The answer lands the note in a pattern. A
//! pattern whose live supporting notes reach `coach.attribution_label_receipts`
//! distinct outcomes files one Proposed `coach.attribution_label.proposal`,
//! quoting those notes. The proposal installs nothing: the owner reads it, and
//! a new label is built by hand. One proposal per pattern; an approved,
//! declined or deleted one suppresses the pattern's next filing.
//!
//! No clustering table holds note text. A re-judged note leaves its pattern
//! in the ledger's write; an erased one also takes the proposal that quoted it
//! (`erase_unclear_note_copies_in_txn`). A filed proposal keeps the entities
//! its notes named, so an erase of one still takes it after a re-judgment
//! removed the notes from the ledger (`erase_label_proposals_naming_in_txn`). A choice no rung answered (an
//! exhausted budget, an outage) parks the pass where it stands; the next night
//! resumes there.

mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use self::store::{
    CURSOR, LabelCursor, MEMBER, NoteMember, NotePattern, NoteSupport, PATTERN, SUPPORT,
    member_key, member_note, pattern_key, support_key, take_members_in_txn, unlink_in_txn,
};
use super::coach::{COACH_ATTRIBUTION_LABEL_PROPOSAL_PREDICATE, COACH_ATTRIBUTION_LABELS_FACET};
use super::proposals;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning_setting::{SettingSpec, setting_value_in_txn};
use crate::llm::decision::DecisionLadder;
use crate::model_decision::catalogue::ATTRIBUTION_PATTERN;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, MAX_DECISION_STATE_BYTES,
    Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill_attribution::{
    UnclearAttribution, UnclearNote, UnclearReason, unclear_key, unclear_page_in_txn,
    unclear_row_in_txn,
};
use crate::store::Store;
use crate::{Vault, WriteEnvelope};

/// How many distinct outcomes a pattern's live notes must come from before
/// the Coach proposes a label for it. Canon names no count; two is the least
/// that can recur, and the seed asks for three.
pub const ATTRIBUTION_LABEL_RECEIPTS: SettingSpec = SettingSpec {
    key: "coach.attribution_label_receipts",
    min: 2.0,
    max: 1_000_000.0,
    seed: 3.0,
};

/// Outcomes one page reads.
const PAGE: usize = 64;
/// Outcomes one pass reads at most; the cursor carries the rest to the next.
const ROWS_PER_PASS: usize = 4096;
/// Patterns one choice shows at most: the scope's best supported.
const PATTERNS_SHOWN: usize = 24;
/// The choice's answers besides a pattern.
const NONE: &str = "none";
const NEW: &str = "new";
/// A shown pattern's option: this prefix and its one-based place.
const PATTERN_OPTION: &str = "pattern_";

/// The host's same-pattern question, on its ladder: the principal the answers
/// are for, the dial and learned bands, the host's wording and each choice's
/// anytime budget.
pub struct UnclearPatternDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub budget: Duration,
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttributionLabelReport {
    /// Choices put to the ladder.
    pub asked: usize,
    /// Notes that joined a pattern the scope held.
    pub joined: usize,
    /// Notes that opened a pattern.
    pub opened: usize,
    /// Notes the choice found naming no pattern.
    pub unpatterned: usize,
    /// Proposals filed.
    pub filed: usize,
    /// The pass stopped on its limit or on a choice no rung answered, with
    /// notes left for the next.
    pub parked: bool,
}

/// One choice's answer.
enum PatternAnswer {
    Unpatterned,
    New,
    Joins([u8; 16]),
    Unanswered,
}

/// One note as a choice shows it.
struct Shown<'a> {
    reason: &'static str,
    leaning: Option<&'static str>,
    text: &'a str,
}

impl<'a> Shown<'a> {
    fn of(note: &'a UnclearNote) -> Self {
        Self {
            reason: note.reason.as_str(),
            leaning: note.leaning.map(|label| label.as_str()),
            text: note.note.as_deref().unwrap_or_default(),
        }
    }

    fn state(&self, cut: Option<usize>) -> Value {
        json!({
            "reason": self.reason,
            "leaning": self.leaning,
            "text": cut_text(self.text, cut),
        })
    }
}

/// A pattern as a choice shows it: its id, its support and its exemplar row.
struct ShownPattern {
    id: [u8; 16],
    support: usize,
    row: UnclearAttribution,
    index: usize,
}

impl UnclearPatternDecisions<'_> {
    /// Asks whether `note` describes the same missing label as one of
    /// `patterns`, a new one, or none, as one Choice keyed by `group` and the
    /// note's fingerprint.
    fn ask(
        &self,
        group: &[u8; 32],
        fingerprint: &[u8; 32],
        row: &UnclearAttribution,
        note: &UnclearNote,
        patterns: &[ShownPattern],
    ) -> Result<PatternAnswer> {
        let mut options = vec![NONE.to_owned(), NEW.to_owned()];
        options.extend((1..=patterns.len()).map(|place| format!("{PATTERN_OPTION}{place}")));
        let question = ATTRIBUTION_PATTERN.question(
            &[group.as_slice(), fingerprint.as_slice()],
            self.wording.clone(),
            AnswerContract::Choice {
                options: options.clone(),
            },
        )?;
        let shown = Shown::of(note);
        let exemplars: Vec<Shown<'_>> = patterns
            .iter()
            .map(|pattern| Shown::of(&pattern.row.notes[pattern.index]))
            .collect();
        let evidence: Vec<EntityId> = row
            .context
            .actor
            .into_iter()
            .chain(row.context.skill)
            .collect();
        let decision = self.ladder.run(
            &question,
            self.principal,
            &evidence,
            &bounded_state(row, &shown, &exemplars, &options[2..]),
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        let DecisionAnswer::Choice(label) = decision.answer else {
            return Ok(PatternAnswer::Unanswered);
        };
        Ok(match label.as_str() {
            NONE => PatternAnswer::Unpatterned,
            NEW => PatternAnswer::New,
            other => other
                .strip_prefix(PATTERN_OPTION)
                .and_then(|place| place.parse::<usize>().ok())
                .and_then(|place| place.checked_sub(1))
                .and_then(|at| patterns.get(at))
                .map_or(PatternAnswer::Unanswered, |pattern| {
                    PatternAnswer::Joins(pattern.id)
                }),
        })
    }
}

/// The choice's bounded state: each note's words cut shorter, halving, until
/// the whole fits [`MAX_DECISION_STATE_BYTES`]; `cut_at_bytes` says where.
fn bounded_state(
    row: &UnclearAttribution,
    note: &Shown<'_>,
    patterns: &[Shown<'_>],
    options: &[String],
) -> Value {
    let longest = patterns
        .iter()
        .chain(std::iter::once(note))
        .map(|shown| shown.text.len())
        .max()
        .unwrap_or(0);
    let mut cut = None;
    loop {
        let state = json!({
            "lane": row.lane.as_str(),
            "note": note.state(cut),
            "patterns": patterns
                .iter()
                .zip(options)
                .map(|(pattern, option)| {
                    let mut shown = pattern.state(cut);
                    shown["option"] = Value::from(option.as_str());
                    shown
                })
                .collect::<Vec<_>>(),
            "cut_at_bytes": cut,
        });
        let fits =
            serde_json::to_vec(&state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES);
        cut = match cut {
            _ if fits => return state,
            None if longest > 0 => Some(longest / 2),
            Some(bytes) if bytes > 0 => Some(bytes / 2),
            // Nothing left to cut: the ladder refuses the state.
            _ => return state,
        };
    }
}

fn cut_text(text: &str, cut: Option<usize>) -> &str {
    let Some(cut) = cut else {
        return text;
    };
    let mut end = text.len().min(cut);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn field(hash: &mut blake3::Hasher, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// The scope a note is clustered within: its lane, consent scope and project.
/// Two scopes never share a pattern, however alike their words.
fn group_key(row: &UnclearAttribution) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("oneiron coach attribution-label group v1");
    field(&mut hash, row.lane.as_str().as_bytes());
    match &row.context.scope {
        Some(scope) => {
            hash.update(&[1]);
            field(&mut hash, scope.as_bytes());
        }
        None => {
            hash.update(&[0]);
        }
    }
    match &row.context.project {
        Some(project) => {
            hash.update(&[1]);
            hash.update(project.as_bytes());
        }
        None => {
            hash.update(&[0]);
        }
    }
    *hash.finalize().as_bytes()
}

/// The outcome a note counts as: the attempt it is about, else its own
/// ledger key.
fn outcome_identity(row: &UnclearAttribution) -> String {
    row.context
        .attempt_receipt
        .clone()
        .unwrap_or_else(|| unclear_key(row.lane, &row.reference))
}

/// What a note was judged at: its scope, actor and skill, its reason,
/// leaning, words, judge revision and outcome. A change to any of them asks
/// again, and takes the note out of the pattern it joined: a note re-recorded
/// in another scope never counts in its old one.
fn fingerprint(row: &UnclearAttribution, note: &UnclearNote) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("oneiron coach attribution-label note v1");
    hash.update(&group_key(row));
    for id in [row.context.actor, row.context.skill] {
        match id {
            Some(id) => {
                hash.update(&[1]);
                hash.update(id.as_bytes());
            }
            None => {
                hash.update(&[0]);
            }
        }
    }
    field(&mut hash, note.reason.as_str().as_bytes());
    field(
        &mut hash,
        note.leaning.map_or("", |label| label.as_str()).as_bytes(),
    );
    field(
        &mut hash,
        note.note.as_deref().unwrap_or_default().as_bytes(),
    );
    field(
        &mut hash,
        row.context
            .judge_revision
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    field(&mut hash, outcome_identity(row).as_bytes());
    *hash.finalize().as_bytes()
}

/// The notes a pass puts to the choice: `no_label_fits` ones with words. A
/// note below the floor or outside its lane doubts an existing label; it does
/// not argue for a missing one.
fn candidates(row: &UnclearAttribution) -> impl Iterator<Item = (u32, &UnclearNote)> {
    row.notes.iter().enumerate().filter_map(|(index, note)| {
        let worded = note
            .note
            .as_deref()
            .is_some_and(|text| !text.trim().is_empty());
        (note.reason == UnclearReason::NoLabelFits && worded)
            .then(|| u32::try_from(index).ok().map(|index| (index, note)))
            .flatten()
    })
}

/// The live note member key `key` names, read in `txn`, when it still holds
/// the fingerprint `member` was judged at.
fn live_note_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<(UnclearAttribution, usize)>> {
    let Some((outcome, index)) = member_note(key) else {
        return Ok(None);
    };
    let Some(row) = unclear_row_in_txn(vault, txn, &outcome)? else {
        return Ok(None);
    };
    let Some(note) = row.notes.get(index) else {
        return Ok(None);
    };
    let Some(member) = MEMBER.get(&vault.store, txn, &key.to_vec())? else {
        return Ok(None);
    };
    if member.fingerprint != fingerprint(&row, note) {
        return Ok(None);
    }
    Ok(Some((row, index)))
}

/// The scope's patterns a choice shows: each one's exemplar note as it stands,
/// best supported first.
fn shown_patterns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: &[u8; 32],
) -> Result<Vec<ShownPattern>> {
    let mut support: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for key in SUPPORT.scan_keys(&vault.store, txn, group)? {
        if let Some(id) = key.get(32..48).and_then(|id| <[u8; 16]>::try_from(id).ok()) {
            *support.entry(id).or_default() += 1;
        }
    }
    let mut shown = Vec::new();
    for (key, pattern) in PATTERN.scan_from(&vault.store, txn, group)? {
        let Some(id) = key.get(32..48).and_then(|id| <[u8; 16]>::try_from(id).ok()) else {
            continue;
        };
        let Some(exemplar) = pattern.exemplar else {
            continue;
        };
        let Some((row, index)) = live_note_in_txn(vault, txn, &exemplar)? else {
            continue;
        };
        shown.push(ShownPattern {
            id,
            support: support.get(&id).copied().unwrap_or(0),
            row,
            index,
        });
    }
    shown.sort_by(|a, b| b.support.cmp(&a.support).then(a.id.cmp(&b.id)));
    shown.truncate(PATTERNS_SHOWN);
    Ok(shown)
}

/// One pass's fixed inputs.
struct Pass<'a> {
    vault: &'a Vault,
    envelope: WriteEnvelope,
    receipts: usize,
    now: u64,
}

impl Pass<'_> {
    /// Lands `answer` for note `index` of `row` under ledger key `key`, if the
    /// note still stands as the choice read it, and files the pattern's
    /// proposal when it became due. Returns whether a proposal was filed.
    fn settle(
        &self,
        key: &str,
        index: u32,
        group: [u8; 32],
        print: [u8; 32],
        answer: &PatternAnswer,
    ) -> Result<bool> {
        let vault = self.vault;
        let member = member_key(key, index);
        vault.with_write_txn_grouped(|txn| {
            let Some(current) = unclear_row_in_txn(vault, &*txn, key)? else {
                return Ok(false);
            };
            let Some(note) = usize::try_from(index)
                .ok()
                .and_then(|at| current.notes.get(at))
            else {
                return Ok(false);
            };
            if fingerprint(&current, note) != print {
                return Ok(false);
            }
            let pattern = match answer {
                PatternAnswer::Unanswered => return Ok(false),
                PatternAnswer::Unpatterned => None,
                PatternAnswer::New => {
                    let id = *vault.store.clock.entity_id()?.as_bytes();
                    PATTERN.put(
                        &vault.store,
                        txn,
                        &pattern_key(&group, &id),
                        &NotePattern {
                            exemplar: Some(member.clone()),
                            proposal: None,
                            filed: Vec::new(),
                            sources: Vec::new(),
                        },
                    )?;
                    Some(id)
                }
                PatternAnswer::Joins(id) => {
                    // A pattern gone since the choice read it: the note waits
                    // for the next pass.
                    if !PATTERN.contains(&vault.store, &*txn, &pattern_key(&group, id))? {
                        return Ok(false);
                    }
                    Some(*id)
                }
            };
            if let Some(old) = MEMBER.get(&vault.store, &*txn, &member)? {
                unlink_in_txn(&vault.store, txn, &member, &old)?;
            }
            MEMBER.put(
                &vault.store,
                txn,
                &member,
                &NoteMember {
                    group,
                    pattern,
                    fingerprint: print,
                },
            )?;
            let Some(pattern) = pattern else {
                return Ok(false);
            };
            SUPPORT.put(
                &vault.store,
                txn,
                &support_key(&group, &pattern, &member),
                &NoteSupport {
                    outcome: outcome_identity(&current),
                },
            )?;
            self.file_if_due_in_txn(txn, &group, &pattern)
        })
    }

    /// Files the pattern's proposal once its live notes come from enough
    /// distinct outcomes. A support whose note changed or left is dropped
    /// here; a pattern already filed is not filed again.
    fn file_if_due_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        group: &[u8; 32],
        pattern_id: &[u8; 16],
    ) -> Result<bool> {
        let vault = self.vault;
        let held = pattern_key(group, pattern_id);
        let Some(mut pattern) = PATTERN.get(&vault.store, &*txn, &held)? else {
            return Ok(false);
        };
        if pattern.proposal.is_some() {
            return Ok(false);
        }
        let mut live = Vec::new();
        let mut stale = Vec::new();
        for (key, support) in SUPPORT.scan_from(&vault.store, &*txn, &held)? {
            let member = key[held.len()..].to_vec();
            match live_note_in_txn(vault, &*txn, &member)? {
                Some((row, index)) => live.push((member, support.outcome, row, index)),
                None => stale.push(key),
            }
        }
        for key in &stale {
            SUPPORT.delete(&vault.store, txn, key)?;
        }
        let outcomes: BTreeSet<&str> = live
            .iter()
            .map(|(_, outcome, _, _)| outcome.as_str())
            .collect();
        if outcomes.len() < self.receipts {
            return Ok(false);
        }
        let Some(exemplar) = pattern
            .exemplar
            .as_ref()
            .and_then(|exemplar| live.iter().find(|(member, ..)| member == exemplar))
            .or_else(|| live.first())
        else {
            return Ok(false);
        };
        let (_, _, exemplar_row, exemplar_index) = exemplar;
        let mut evidence = BTreeSet::new();
        for (_, _, row, _) in &live {
            for id in row
                .context
                .actor
                .iter()
                .chain(&row.context.skill)
                .chain(&row.context.sources)
            {
                if !crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &*txn, id)?
                    .deleted
                {
                    evidence.insert(*id);
                }
            }
        }
        // A proposal cites live rows; with none, the pattern waits.
        if evidence.is_empty() {
            return Ok(false);
        }
        let value = json!({
            "kind": "attribution_label_addition",
            "pattern": crate::entity_id::bytes_to_hex_lower(pattern_id),
            "lane": exemplar_row.lane.as_str(),
            "scope": exemplar_row.context.scope,
            "project": exemplar_row.context.project.map(|id| id.to_hex()),
            "description": exemplar_row.notes[*exemplar_index].note,
            "threshold": self.receipts,
            "outcomes": outcomes,
            "notes": live
                .iter()
                .map(|(_, outcome, row, index)| {
                    let note = &row.notes[*index];
                    json!({
                        "outcome": outcome,
                        "reference": row.reference,
                        "reason": note.reason.as_str(),
                        "leaning": note.leaning.map(|label| label.as_str()),
                        "confidence": note.confidence,
                        "share": note.share,
                        "note": note.note,
                        "actor": row.context.actor.map(|id| id.to_hex()),
                        "skill": row.context.skill.map(|id| id.to_hex()),
                        "judge_revision": row.context.judge_revision,
                        "judge_model": row.context.judge_model,
                        "at": row.at,
                    })
                })
                .collect::<Vec<_>>(),
            "judged_by": ATTRIBUTION_PATTERN.name,
            "installs_label": false,
        });
        let evidence: Vec<EntityId> = evidence.into_iter().collect();
        let proposal = proposals::emit_in_txn(
            vault,
            txn,
            crate::dreamer_runner::authority::coach_actor_id()?,
            COACH_ATTRIBUTION_LABEL_PROPOSAL_PREDICATE,
            &value,
            &evidence,
            &self.envelope,
            self.now,
        )?;
        let named: BTreeSet<[u8; 16]> = live
            .iter()
            .flat_map(|(_, _, row, _)| {
                row.context
                    .actor
                    .iter()
                    .chain(&row.context.skill)
                    .chain(&row.context.project)
                    .chain(&row.context.sources)
                    .map(|id| *id.as_bytes())
                    .collect::<Vec<_>>()
            })
            .collect();
        pattern.proposal = Some(*proposal.as_bytes());
        pattern.sources = named.into_iter().collect();
        pattern.filed = live.into_iter().map(|(member, ..)| member).collect();
        PATTERN.put(&vault.store, txn, &held, &pattern)?;
        Ok(true)
    }
}

impl Vault {
    /// The unclear-note clustering as the Coach, under a leased
    /// `coach.attribution_labels` attempt: at most `limit` choices through
    /// `decisions`, each outside any vault transaction and settled in its own
    /// write. The pass stops early on a choice no rung answered; the cursor
    /// keeps its place.
    ///
    /// # Errors
    ///
    /// An attempt that is not the Coach's clustering job; storage errors and
    /// whatever the decision path returns.
    pub fn run_coach_attribution_labels(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &UnclearPatternDecisions<'_>,
        limit: usize,
        now: u64,
    ) -> Result<AttributionLabelReport> {
        self.require_coach_attempt(attempt, COACH_ATTRIBUTION_LABELS_FACET)?;
        let (mut after, receipts) = {
            let rtxn = self.store.env.read_txn()?;
            let after = CURSOR
                .get(&self.store, &rtxn, &())?
                .and_then(|cursor| cursor.after);
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a catalog count clamped to 2..=1e6 and rounded up"
            )]
            let receipts = setting_value_in_txn(&self.store, &rtxn, &ATTRIBUTION_LABEL_RECEIPTS)?
                .ceil() as usize;
            (after, receipts)
        };
        let pass = Pass {
            vault: self,
            envelope: proposals::run_tray_envelope(
                self,
                COACH_ATTRIBUTION_LABELS_FACET,
                attempt.status.attempt.id,
            )?,
            receipts,
            now,
        };
        let mut report = AttributionLabelReport::default();
        let mut read = 0_usize;
        let mut wrapped = false;
        'pages: loop {
            let page = {
                let rtxn = self.store.env.read_txn()?;
                unclear_page_in_txn(self, &rtxn, after.as_deref(), PAGE)?
            };
            if page.is_empty() {
                // The ledger's end: the next page starts over, once a pass.
                if after.is_none() || wrapped {
                    after = None;
                    break;
                }
                after = None;
                wrapped = true;
                continue;
            }
            for (key, row) in page {
                if read == ROWS_PER_PASS {
                    report.parked = true;
                    break 'pages;
                }
                read += 1;
                let group = group_key(&row);
                for (index, note) in candidates(&row) {
                    let member = member_key(&key, index);
                    let print = fingerprint(&row, note);
                    let (judged, shown) = {
                        let rtxn = self.store.env.read_txn()?;
                        let judged = MEMBER
                            .get(&self.store, &rtxn, &member)?
                            .is_some_and(|held| held.fingerprint == print);
                        let shown = if judged || report.asked == limit {
                            Vec::new()
                        } else {
                            shown_patterns_in_txn(self, &rtxn, &group)?
                        };
                        (judged, shown)
                    };
                    if judged {
                        continue;
                    }
                    if report.asked == limit {
                        report.parked = true;
                        break 'pages;
                    }
                    let answer = decisions.ask(&group, &print, &row, note, &shown)?;
                    report.asked += 1;
                    match answer {
                        PatternAnswer::Unanswered => {
                            report.parked = true;
                            break 'pages;
                        }
                        PatternAnswer::Unpatterned => report.unpatterned += 1,
                        PatternAnswer::New => report.opened += 1,
                        PatternAnswer::Joins(_) => report.joined += 1,
                    }
                    if pass.settle(&key, index, group, print, &answer)? {
                        report.filed += 1;
                    }
                }
                after = Some(key);
            }
        }
        self.with_write_txn(|txn| {
            CURSOR.put(&self.store, txn, &(), &LabelCursor { after })?;
            Ok(())
        })?;
        Ok(report)
    }
}

/// Takes the notes of the outcome under unclear-ledger key `outcome` out of
/// the clustering: a re-judgment withdrew or replaced them. A proposal that
/// quoted one stands; it was true when filed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn forget_unclear_notes_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    outcome: &str,
) -> Result<()> {
    for (key, member) in take_members_in_txn(store, txn, outcome)? {
        unlink_in_txn(store, txn, &key, &member)?;
    }
    Ok(())
}

/// Takes the erased outcome under unclear-ledger key `outcome` out of the
/// clustering, and erases each proposal that quoted one of its notes: the
/// generated claim and its machine history go, as a mined copy's do. The
/// pattern keeps its other notes and may file again from them.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_unclear_note_copies_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    outcome: &str,
) -> Result<()> {
    let store = write.store;
    for (key, member) in take_members_in_txn(store, txn, outcome)? {
        let Some(pattern_id) = unlink_in_txn(store, txn, &key, &member)? else {
            continue;
        };
        let held = pattern_key(&member.group, &pattern_id);
        let Some(pattern) = PATTERN.get(store, &*txn, &held)? else {
            continue;
        };
        if !pattern.filed.contains(&key) {
            continue;
        }
        withdraw_filed_in_txn(write, txn, &held, pattern)?;
    }
    Ok(())
}

/// Erases every filed proposal whose quoted notes named erased `entity`, by
/// the sources frozen at filing (FIX 7824): a note re-judged out of the
/// ledger since still had its words copied into the proposal. A pattern row
/// that does not decode goes.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_label_proposals_naming_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let store = write.store;
    let rows = PATTERN
        .iter_raw_from(store, &*txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        let Ok(pattern) = PATTERN.decode_value(&value) else {
            PATTERN.delete(store, txn, &key)?;
            continue;
        };
        if pattern.proposal.is_some() && pattern.sources.contains(entity.as_bytes()) {
            withdraw_filed_in_txn(write, txn, &key, pattern)?;
        }
    }
    Ok(())
}

/// Erases `pattern`'s filed proposal and forgets what it quoted; the pattern
/// keeps its notes and may file again from them, or goes with none left.
fn withdraw_filed_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    held: &[u8],
    mut pattern: NotePattern,
) -> Result<()> {
    let store = write.store;
    pattern.filed.clear();
    pattern.sources.clear();
    if let Some(proposal) = pattern.proposal.take() {
        erase_proposal_copy_in_txn(write, txn, &EntityId::from_bytes(proposal)?)?;
    }
    if pattern.exemplar.is_some() {
        PATTERN.put(store, txn, &held.to_vec(), &pattern)?;
    } else {
        PATTERN.delete(store, txn, &held.to_vec())?;
    }
    Ok(())
}

/// Erases one filed proposal with its machine history: the miner's copy
/// erase, for a claim that quotes an erased note.
fn erase_proposal_copy_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
) -> Result<()> {
    let store = write.store;
    let (existed, vector, graph, neighbors) =
        crate::batch::deindex_entity_with_machine_history(write, txn, proposal)?;
    if !existed {
        return Ok(());
    }
    crate::batch::stage_cascade_tombstone_in_txn(store, txn, proposal)?;
    crate::ppr::invalidate_ppr_for_delete(store, txn, proposal, &neighbors)?;
    if graph {
        crate::ppr::increment_graph_version(store, txn)?;
    }
    if vector {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    Ok(())
}
