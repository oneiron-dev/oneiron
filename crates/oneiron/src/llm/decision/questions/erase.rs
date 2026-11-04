//! The erase door for typed questions by unit and by principal (FIX 11236).
//!
//! An erase-only decl scrub on `TYPED_QUESTION`: the actor sweep runs it in
//! the erase's own transaction, never on a reversible delete (delete
//! restores; erase is one-way). It takes both shapes of `id` in one pass,
//! with no actor gate: a unit is usually no actor. FIX 9918's answer-claim
//! arm (`lifetime.rs`) and the ask-history scrub keep their rows; this one
//! adds the unit legs, the principal families and the graph-claim join the
//! ask-history scrub cannot see.
//!
//! A principal erase deletes the whole family of every question whose any
//! version names `id` as its principal: all versions, the head, every
//! answer with its labels and window, the backfill dedups and schedule,
//! the ask-history entries and mark, the pending, unit-watch, rests-on and
//! root-source legs, the predicate watches, the artifact-asked stamps and
//! the unit asks. Nothing stays: reads admit the principal alone, so a
//! surviving row would strand unreadable, unrefreshable debt.
//!
//! A unit erase deletes the rows that copy or derive from `id`: each answer
//! on that unit with its labels and window, the backfill dedups and joins
//! naming it, the pending, unit-watch, rests-on and root-source legs, the
//! artifact-asked stamps, the unit asks and the graph history entries of
//! its deleted answers. The immutable version id lists (`units`,
//! `artifacts`) and the predicate-only watch rows stay: every read
//! rechecks liveness and authority, so a dangling id is safe. A one-unit
//! `tasks.ask` or health question is its one answer, so its one version,
//! its matching head and its watch go with the answer, as FIX 9918 does.

use std::collections::BTreeSet;

use super::arrival::{PENDING, RESTS_ON, ROOT_SOURCES, UNIT_WATCH, unwatch};
use super::artifact_refresh::ASKED;
use super::ask_history::{ASK_HISTORY, ASK_HISTORY_HEAD, AskHistoryEvent, AskHistoryHeadKey};
use super::backfill::{BackfillAtKey, QUESTION_BACKFILL_AT};
use super::role_asks::UNIT_ASKS;
use super::standing::{BackfillKey, QUESTION_BACKFILL};
use super::store::{
    AnswerKey, HeadKey, LabelKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_LABEL, QUESTION_VERSION,
    VersionKey, secret_scan_before_put,
};
use super::windows::{QUESTION_WINDOW, WindowKey};
use crate::side_table::SideKey;
use crate::{EntityId, Result, Vault};

/// Adapters whose one version carries its one answer's selection: a
/// `tasks.ask` ask and a wire-health check are each one one-off question
/// over one unit, so the version goes with the answer.
const ONE_UNIT_ADAPTERS: [&str; 2] = ["tasks.ask", "wire.health"];

/// Erases `id`'s typed-question rows in the erase's own transaction: the
/// whole family of every question it is a principal of, and every row that
/// copies or derives from it as a unit. Runs on erase only, never on a
/// reversible delete.
pub(crate) fn erase_questions_for_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    // One pass over the shared rows, keys first: each family decodes its
    // own keys, and only the families this erase reads decode values.
    let mut versions = Vec::new();
    let mut answers = Vec::new();
    let mut labels = Vec::new();
    let mut windows = Vec::new();
    let mut heads = Vec::new();
    let mut backfills = Vec::new();
    let mut backfill_ats = Vec::new();
    let mut history_heads = Vec::new();
    for row in QUESTION_VERSION.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, value) = row?;
        // A row that does not decode is passed over with a WARN: the erase
        // never fails on it.
        if let Some(version) = VersionKey::decode_key(&key) {
            match QUESTION_VERSION.decode_value(&value) {
                Ok(record) => versions.push((version, record)),
                Err(_) => {
                    tracing::warn!("a question version does not decode: the erase passes it over")
                }
            }
        } else if let Some(answer) = AnswerKey::decode_key(&key) {
            match QUESTION_ANSWER.decode_value(&value) {
                Ok(record) => answers.push((answer, record)),
                Err(_) => {
                    tracing::warn!("a question answer does not decode: the erase passes it over")
                }
            }
        } else if let Some(label) = LabelKey::decode_key(&key) {
            labels.push(label);
        } else if let Some(window) = WindowKey::decode_key(&key) {
            windows.push(window);
        } else if let Some(head) = HeadKey::decode_key(&key) {
            heads.push(head);
        } else if let Some(backfill) = BackfillKey::decode_key(&key) {
            backfills.push(backfill);
        } else if let Some(at) = BackfillAtKey::decode_key(&key) {
            match QUESTION_BACKFILL_AT.decode_value(&value) {
                Ok(scheduled) => backfill_ats.push((at, scheduled)),
                Err(_) => {
                    tracing::warn!("a scheduled backfill does not decode: the erase passes it over")
                }
            }
        } else if let Some(mark) = AskHistoryHeadKey::decode_key(&key) {
            history_heads.push(mark);
        }
    }
    // Every question whose any version names `id` as its principal goes
    // whole; every answer on `id` as its unit goes with its copies.
    let mut doomed = BTreeSet::new();
    for (version, record) in &versions {
        if record.principal == *id {
            doomed.insert(version.id);
        }
    }
    let mut dead: BTreeSet<(EntityId, EntityId)> = BTreeSet::new();
    for (answer, record) in &answers {
        if doomed.contains(&answer.question) || record.unit == *id {
            dead.insert((answer.question, answer.claim));
        }
    }
    // A one-unit one-off version is its one answer: the version goes with
    // a unit-erased answer, as FIX 9918's cascade does.
    let mut cascades = Vec::new();
    for (answer, record) in &answers {
        if record.unit != *id || doomed.contains(&answer.question) {
            continue;
        }
        let version = record.decision.receipt.question_version;
        let found = versions
            .iter()
            .find(|(key, _)| key.id == answer.question && key.version == version);
        let Some((key, versioned)) = found else {
            continue;
        };
        if ONE_UNIT_ADAPTERS.contains(&versioned.definition.adapter.as_str())
            && versioned.definition.units.len() == 1
            && !cascades.contains(key)
        {
            cascades.push(*key);
        }
    }
    // The sibling passes, keys first: each table scans whole, then its
    // doomed and unit-named rows go after the scan. The unit-watch legs go
    // by the unit's prefix; a doomed question's legs go with its watch.
    let mut history = Vec::new();
    for (key, entry) in ASK_HISTORY.scan(&vault.store, wtxn)? {
        let graph_dead = matches!(
            &entry.event,
            AskHistoryEvent::Graph { claim } if dead.contains(&(key.question, *claim))
        );
        if doomed.contains(&key.question) || entry.principal == *id || graph_dead {
            history.push(key);
        }
    }
    let mut pending = Vec::new();
    for (key, _) in PENDING.scan(&vault.store, wtxn)? {
        if doomed.contains(&key.0) || key.1 == *id {
            pending.push(key);
        }
    }
    let unit_watch: Vec<(EntityId, EntityId)> = UNIT_WATCH
        .scan_from(&vault.store, wtxn, id.as_bytes())?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let mut rests: Vec<(EntityId, EntityId, EntityId)> = RESTS_ON
        .scan_from(&vault.store, wtxn, id.as_bytes())?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    for (key, _) in RESTS_ON.scan(&vault.store, wtxn)? {
        if (doomed.contains(&key.1) || key.2 == *id) && !rests.contains(&key) {
            rests.push(key);
        }
    }
    let mut roots = Vec::new();
    for (key, _) in ROOT_SOURCES.scan(&vault.store, wtxn)? {
        if doomed.contains(&key.0) || key.1 == *id {
            roots.push(key);
        }
    }
    let mut asked = Vec::new();
    for (key, stamp) in ASKED.scan(&vault.store, wtxn)? {
        if doomed.contains(&key.0)
            || key.1 == *id
            || stamp.versions.iter().any(|(read, _)| read == id)
        {
            asked.push(key);
        }
    }
    let mut unit_asks = Vec::new();
    for (seq, ask) in UNIT_ASKS.scan(&vault.store, wtxn)? {
        if ask.unit == *id || ask.declined.receipt.principal == *id {
            unit_asks.push(seq);
        }
    }
    // The deletes, after every scan: answers with their labels and
    // windows first, then the owning rows, then the legs and stamps.
    for (answer, _) in &answers {
        if dead.contains(&(answer.question, answer.claim)) {
            QUESTION_ANSWER.delete(&vault.store, wtxn, answer)?;
        }
    }
    for label in &labels {
        let gone =
            doomed.contains(&label.question) || dead.contains(&(label.question, label.claim));
        if gone {
            QUESTION_LABEL.delete(&vault.store, wtxn, label)?;
        }
    }
    for window in &windows {
        let gone =
            doomed.contains(&window.question) || dead.contains(&(window.question, window.claim));
        if gone {
            QUESTION_WINDOW.delete(&vault.store, wtxn, window)?;
        }
    }
    for (version, record) in &versions {
        if doomed.contains(&version.id) {
            QUESTION_VERSION.delete(&vault.store, wtxn, version)?;
            unwatch(&vault.store, wtxn, record)?;
        }
    }
    for version in &cascades {
        QUESTION_VERSION.delete(&vault.store, wtxn, version)?;
        if QUESTION_HEAD
            .get(&vault.store, wtxn, &HeadKey(version.id))?
            .is_some_and(|head| head.version == version.version)
        {
            QUESTION_HEAD.delete(&vault.store, wtxn, &HeadKey(version.id))?;
        }
        if let Some((_, record)) = versions.iter().find(|(key, _)| key == version) {
            unwatch(&vault.store, wtxn, record)?;
        }
    }
    for head in &heads {
        if doomed.contains(&head.0) {
            QUESTION_HEAD.delete(&vault.store, wtxn, head)?;
        }
    }
    for backfill in &backfills {
        if doomed.contains(&backfill.question) || backfill.unit == *id {
            QUESTION_BACKFILL.delete(&vault.store, wtxn, backfill)?;
        }
    }
    for (at, backfill) in &mut backfill_ats {
        if doomed.contains(&at.0) {
            QUESTION_BACKFILL_AT.delete(&vault.store, wtxn, at)?;
        } else {
            let before = backfill.joins.len();
            backfill
                .joins
                .retain(|join| join.unit != *id && !join.evidence.contains(id));
            if backfill.joins.len() != before {
                secret_scan_before_put(backfill)?;
                QUESTION_BACKFILL_AT.put(&vault.store, wtxn, at, backfill)?;
            }
        }
    }
    for mark in &history_heads {
        if doomed.contains(&mark.0) {
            ASK_HISTORY_HEAD.delete(&vault.store, wtxn, mark)?;
        }
    }
    for key in &history {
        ASK_HISTORY.delete(&vault.store, wtxn, key)?;
    }
    for key in &pending {
        PENDING.delete(&vault.store, wtxn, key)?;
    }
    for key in &unit_watch {
        UNIT_WATCH.delete(&vault.store, wtxn, key)?;
    }
    for key in &rests {
        RESTS_ON.delete(&vault.store, wtxn, key)?;
    }
    for key in &roots {
        ROOT_SOURCES.delete(&vault.store, wtxn, key)?;
    }
    for key in &asked {
        ASKED.delete(&vault.store, wtxn, key)?;
    }
    for seq in &unit_asks {
        UNIT_ASKS.delete(&vault.store, wtxn, seq)?;
    }
    Ok(())
}
