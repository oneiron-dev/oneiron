//! The auto check's verdict cache (ARCH-0055, "checker/classifier verdicts
//! key on (content-hash, policy-version) with TTL"): a decided verdict is
//! reused for the same candidate under the same effective policy until its
//! TTL ends, so a repeated action shape skips the model. Only the checker's
//! one worker reads and writes it, after the caller's turn was admitted as
//! before; a candidate the cache does not hold goes to the ladder.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::json;

use super::super::decision::catalogue::AUTO_CHECK;
use super::super::decision::{AnswerContract, Reversibility};
use super::candidate_state;
use super::{ALLOW, AutoCheckCandidate, AutoCheckDecisions, AutoCheckOutcome, HOLD};

/// How long a decided verdict stands for the same candidate under the same
/// effective policy. Canon names a TTL and no number (CALLS: auto-check
/// verdict TTL).
pub(super) const AUTO_CHECK_VERDICT_TTL: Duration = Duration::from_secs(10 * 60);

/// The most verdicts the cache holds; past it the oldest goes first. A bound
/// on the worker's memory, never a refusal (CALLS: auto-check verdict cache
/// size).
pub(super) const AUTO_CHECK_VERDICT_CACHE_ENTRIES: usize = 4_096;

/// A cached verdict's key: the hash of the candidate as the ladder reads it,
/// and the hash of the effective policy that decides it.
type VerdictKey = ([u8; 32], [u8; 32]);

/// The checker worker's decided verdicts, oldest first.
#[derive(Default)]
pub(super) struct VerdictCache {
    verdicts: HashMap<VerdictKey, AutoCheckOutcome>,
    order: VecDeque<(Instant, VerdictKey)>,
}

impl VerdictCache {
    /// `decisions`' normalized verdict on `candidate`: a current cached one
    /// for the same content under the same effective policy, else the
    /// ladder's, kept when it decided. An unavailable check is never kept.
    pub(super) fn check(
        &mut self,
        decisions: &AutoCheckDecisions,
        candidate: &AutoCheckCandidate<'_>,
        due: Instant,
    ) -> AutoCheckOutcome {
        let Some(key) = decisions.verdict_key(candidate) else {
            return decisions.check(candidate, due).normalized();
        };
        let now = Instant::now();
        self.expire(now);
        if let Some(outcome) = self.verdicts.get(&key) {
            return outcome.clone();
        }
        let outcome = decisions.check(candidate, due).normalized();
        if outcome != AutoCheckOutcome::Unavailable {
            self.keep(key, outcome.clone(), now);
        }
        outcome
    }

    /// Drops every verdict whose TTL ended by `now`.
    fn expire(&mut self, now: Instant) {
        while let Some((at, key)) = self.order.front().copied() {
            if now.saturating_duration_since(at) < AUTO_CHECK_VERDICT_TTL {
                break;
            }
            self.order.pop_front();
            self.verdicts.remove(&key);
        }
    }

    /// Keeps `outcome` under `key` from `now`, the oldest verdict going first
    /// once the cache is full.
    fn keep(&mut self, key: VerdictKey, outcome: AutoCheckOutcome, now: Instant) {
        while self.verdicts.len() >= AUTO_CHECK_VERDICT_CACHE_ENTRIES {
            let Some((_, oldest)) = self.order.pop_front() else {
                break;
            };
            self.verdicts.remove(&oldest);
        }
        self.verdicts.insert(key, outcome);
        self.order.push_back((now, key));
    }
}

impl AutoCheckDecisions {
    /// The cache key of this check of `candidate`: the content hash of the
    /// state the ladder reads, and the hash of the effective policy that
    /// decides it (the question's id and version, the dial, the band row in
    /// force and its version, the think and person rows' versions, the
    /// calibrated model and every rung's pin). None when either does not
    /// encode: that check is not cached.
    fn verdict_key(&self, candidate: &AutoCheckCandidate<'_>) -> Option<VerdictKey> {
        let question = AUTO_CHECK
            .question(
                &[],
                self.wording.clone(),
                AnswerContract::Choice {
                    options: vec![ALLOW.to_owned(), HOLD.to_owned()],
                },
            )
            .ok()?;
        let band = self
            .bands
            .resolve(&question, Reversibility::OutboundEffect, self.dial.band)
            .ok()?;
        let ladder = self.ladder.ladder();
        let pins: Vec<_> = [
            ladder.rule,
            ladder.local,
            ladder.system_one,
            ladder.escalation,
            ladder.big,
        ]
        .into_iter()
        .map(|slot| slot.map(|provider| provider.pin()))
        .collect();
        let policy = serde_json::to_vec(&json!({
            "question": question.id.to_hex(),
            "question_version": question.version,
            "dial": self.dial,
            "band": band,
            "think": self.bands.think_threshold().map(|row| row.version),
            "person": self.bands.person_threshold().map(|row| row.version),
            "calibrated": self.calibrated,
            "pins": pins,
            "human_pin": ladder.human_pin,
        }))
        .ok()?;
        let content = serde_json::to_vec(&candidate_state(candidate)).ok()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.autocheck.verdict_policy.v1");
        hasher.update(&policy);
        Some((
            *blake3::hash(&content).as_bytes(),
            *hasher.finalize().as_bytes(),
        ))
    }
}
