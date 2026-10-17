//! The sufficiency card and the sparse owner-label ask (ARCH-0053; NOT-WORSE
//! = A, EVAL-COLDSTART = C).
//!
//! The card shows independent families, floor-slice family counts, retest
//! noise, the family-grouped paired interval, the detectable effect and the
//! margin. A candidate is not worse when the interval's low end, grouped by
//! family, exceeds minus the margin. Seat retest noise is the default margin,
//! and the owner may only make it stricter. "It reads unknown when the
//! interval spans the margin or a floor slice has too few families", and when
//! the set, the rubric or the canary moved. An unknown card never approves.
//!
//! The owner is asked for a label "only when a real decision waits on a set
//! that is too small". There is no standing labelling session: an ask names
//! the decision that waits, and the minutes it is shown to cost come from the
//! judge-calibration policy row. A digest carries it once, paid from the same
//! funded minutes as the judge asks.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    EvalCase, EvalLabel, EvalLabelKind, EvalSeat, append_label_in_txn, case_in_txn, invalid,
    rows_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub(in crate::skill_optimize) const LABEL_ASK_PREFIX: &[u8] = b"skill_optimize:eval_label_ask:v1:";
const ASK_DOMAIN: &[u8] = b"skill_optimize:eval_label_ask:v1\0";
const MAX_TEXT_BYTES: usize = 512;

/// The measurements a card is read from. Every number is supplied by the
/// measuring workflow; the card computes nothing it was not given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SufficiencyInput {
    /// Independent source families in the set.
    pub families: u32,
    /// Families per floor slice, by slice.
    pub floor_slices: BTreeMap<String, u32>,
    /// The fewest families a floor slice needs: the skill's or the owner's
    /// policy, never a default here.
    pub min_families_per_slice: u32,
    /// The seat's retest noise, the default margin.
    pub retest_noise: Option<f64>,
    /// The owner's margin; it can only be stricter than the noise.
    pub owner_margin: Option<f64>,
    /// Candidate minus incumbent on identical tasks, grouped by family.
    pub paired_interval: Option<(f64, f64)>,
    pub detectable_effect: Option<f64>,
    /// The set or rubric version moved since the incumbent was measured.
    pub set_changed: bool,
    pub rubric_changed: bool,
    pub canary_diverged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    NoRetestNoise,
    NoInterval,
    IntervalSpansMargin,
    TooFewFamilies { slice: String, families: u32 },
    SetChanged,
    RubricChanged,
    CanaryDiverged,
}

impl UnknownReason {
    /// Whether more labelled cases could settle it.
    const fn labels_help(&self) -> bool {
        matches!(
            self,
            Self::NoInterval | Self::IntervalSpansMargin | Self::TooFewFamilies { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SufficiencyVerdict {
    NotWorse,
    Worse,
    Unknown(Vec<UnknownReason>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SufficiencyCard {
    pub input: SufficiencyInput,
    /// The margin in force: the noise, or the owner's stricter one.
    pub margin: Option<f64>,
    pub verdict: SufficiencyVerdict,
}

impl SufficiencyCard {
    /// Only a not-worse card may let a decision proceed without a person.
    #[must_use]
    pub fn approves(&self) -> bool {
        self.verdict == SufficiencyVerdict::NotWorse
    }
}

fn nonnegative(value: Option<f64>) -> Result<()> {
    if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
        return Err(invalid(
            "a sufficiency measurement must be finite and nonnegative",
        ));
    }
    Ok(())
}

/// Read a card from its measurements.
/// # Errors
/// A negative or non-finite noise, margin or effect, or a reversed or
/// non-finite interval.
pub fn sufficiency_card(input: SufficiencyInput) -> Result<SufficiencyCard> {
    nonnegative(input.retest_noise)?;
    nonnegative(input.owner_margin)?;
    nonnegative(input.detectable_effect)?;
    if input
        .paired_interval
        .is_some_and(|(low, high)| !low.is_finite() || !high.is_finite() || low > high)
    {
        return Err(invalid("a paired interval must be finite and ordered"));
    }
    let margin = input
        .retest_noise
        .map(|noise| input.owner_margin.map_or(noise, |owner| owner.min(noise)));
    let mut unknown = Vec::new();
    if input.set_changed {
        unknown.push(UnknownReason::SetChanged);
    }
    if input.rubric_changed {
        unknown.push(UnknownReason::RubricChanged);
    }
    if input.canary_diverged {
        unknown.push(UnknownReason::CanaryDiverged);
    }
    for (slice, families) in &input.floor_slices {
        if *families < input.min_families_per_slice.max(1) {
            unknown.push(UnknownReason::TooFewFamilies {
                slice: slice.clone(),
                families: *families,
            });
        }
    }
    let mut worse = false;
    match (margin, input.paired_interval) {
        (None, _) => unknown.push(UnknownReason::NoRetestNoise),
        (_, None) => unknown.push(UnknownReason::NoInterval),
        (Some(margin), Some((low, high))) => {
            if high <= -margin {
                worse = true;
            } else if low <= -margin {
                unknown.push(UnknownReason::IntervalSpansMargin);
            }
        }
    }
    let verdict = if worse {
        SufficiencyVerdict::Worse
    } else if unknown.is_empty() {
        SufficiencyVerdict::NotWorse
    } else {
        SufficiencyVerdict::Unknown(unknown)
    };
    Ok(SufficiencyCard {
        input,
        margin,
        verdict,
    })
}

/// A decision that waits on a set, and the card it read.
#[derive(Debug, Clone, PartialEq)]
pub struct WaitingDecision {
    /// The proposal, campaign or offer the decision is about.
    pub reference: String,
    pub card: SufficiencyCard,
}

/// One owner-label question about one case, put because a decision waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalLabelAsk {
    pub id: EntityId,
    pub seat: EvalSeat,
    pub case: EntityId,
    pub decision: String,
    pub responsible: EntityId,
    pub option_a: String,
    pub option_b: String,
    /// The minutes the ask is shown to cost.
    pub minutes: u32,
    pub asked_at: u64,
    /// When a digest carried it: only a delivery marker, never an answer.
    pub delivered_at: Option<u64>,
    pub chosen: Option<String>,
    pub answered_at: Option<u64>,
}

fn ask_key(decision: &str, case: &EntityId) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(ASK_DOMAIN);
    hash.update(decision.as_bytes());
    hash.update(b"\0");
    hash.update(case.as_bytes());
    [LABEL_ASK_PREFIX, hash.finalize().as_slice()].concat()
}

fn bounded(text: &str) -> bool {
    !text.trim().is_empty() && text.len() <= MAX_TEXT_BYTES
}

fn encode(row: &EvalLabelAsk) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| invalid("eval label ask encoding failed"))
}

impl Vault {
    /// Ask the responsible person to label one case, only while `waiting`
    /// holds an unknown card that more labels could settle. `None` when the
    /// card is known, or unknown for a reason no label fixes. One ask stands
    /// per decision and case; a repeat returns it.
    /// # Errors
    /// Unbounded text, identical options, a missing case, a responsible id
    /// that is not a live person, an unreadable policy row, or storage errors.
    pub fn ask_eval_label(
        &self,
        waiting: &WaitingDecision,
        case: &EntityId,
        responsible: EntityId,
        option_a: &str,
        option_b: &str,
        at: u64,
    ) -> Result<Option<EvalLabelAsk>> {
        let SufficiencyVerdict::Unknown(reasons) = &waiting.card.verdict else {
            return Ok(None);
        };
        if !reasons.iter().any(UnknownReason::labels_help) {
            return Ok(None);
        }
        if !bounded(&waiting.reference)
            || !bounded(option_a)
            || !bounded(option_b)
            || option_a == option_b
        {
            return Err(invalid("an eval label ask needs bounded, distinct text"));
        }
        self.with_write_txn_grouped(|txn| {
            let key = ask_key(&waiting.reference, case);
            if let Some(raw) = self.store.vault_meta.get(txn, &key)? {
                return Ok(Some(super::decode(&raw)?));
            }
            let row: EvalCase = case_in_txn(self, txn, case)?.ok_or(Error::EntityNotFound)?;
            if !crate::consent::person_is_live_in_txn(self, txn, &responsible)? {
                return Err(invalid("an eval label is asked of a live person"));
            }
            let ask = EvalLabelAsk {
                id: self.store.clock.entity_id()?,
                seat: row.seat,
                case: *case,
                decision: waiting.reference.clone(),
                responsible,
                option_a: option_a.to_owned(),
                option_b: option_b.to_owned(),
                minutes: super::super::policy::resolved_in_txn(self, txn)?.ask_minutes,
                asked_at: at,
                delivered_at: None,
                chosen: None,
                answered_at: None,
            };
            self.store.vault_meta.put(txn, &key, &encode(&ask)?)?;
            Ok(Some(ask))
        })
    }

    /// The open eval label asks `person` is responsible for.
    /// # Errors
    /// Unreadable rows, or storage errors.
    pub fn eval_label_asks_for(&self, person: &EntityId) -> Result<Vec<EvalLabelAsk>> {
        let txn = self.store.env.read_txn()?;
        Ok(rows_in_txn::<EvalLabelAsk>(self, &txn, LABEL_ASK_PREFIX)?
            .into_iter()
            .filter(|ask| &ask.responsible == person && ask.answered_at.is_none())
            .collect())
    }

    /// A digest's draw on the eval label asks `owner` is responsible for: the
    /// unanswered ones no digest carried yet, in key order, while their
    /// minutes fit `budget`. Each one taken is marked delivered at `at` in the
    /// caller's transaction; they return with the minutes they cost.
    /// # Errors
    /// Unreadable rows, or storage errors.
    pub(in crate::skill_optimize) fn take_eval_label_asks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        at: u64,
        budget: u32,
    ) -> Result<(Vec<EvalLabelAsk>, u32)> {
        let mut taken = Vec::new();
        let mut spent = 0_u32;
        for mut ask in rows_in_txn::<EvalLabelAsk>(self, txn, LABEL_ASK_PREFIX)? {
            let pending = ask.answered_at.is_none() && ask.delivered_at.is_none();
            if ask.responsible != owner || !pending {
                continue;
            }
            match spent.checked_add(ask.minutes) {
                Some(total) if total <= budget => spent = total,
                _ => break,
            }
            ask.delivered_at = Some(at);
            let key = ask_key(&ask.decision, &ask.case);
            self.store.vault_meta.put(txn, &key, &encode(&ask)?)?;
            taken.push(ask);
        }
        Ok((taken, spent))
    }

    /// The responsible person's pick: an owner-pick label on the case, the
    /// preference anchor. Once per ask; the same pick again is a no-op and a
    /// different one is refused.
    /// # Errors
    /// No such ask, another person, a conflicting second pick, or storage
    /// errors.
    pub fn record_eval_label_pick(
        &self,
        owner: &AuthenticatedOwner,
        decision: &str,
        case: &EntityId,
        choose_b: bool,
        at: u64,
    ) -> Result<EvalCase> {
        self.with_write_txn_grouped(|txn| {
            let actor =
                crate::dreamer_runner::maintenance::validate_person_in_txn(self, txn, owner)?;
            let key = ask_key(decision, case);
            let mut ask: EvalLabelAsk = super::decode(
                &self
                    .store
                    .vault_meta
                    .get(txn, &key)?
                    .ok_or(Error::EntityNotFound)?,
            )?;
            if ask.responsible != actor {
                return Err(invalid("an eval label pick comes from the person asked"));
            }
            let chosen = if choose_b {
                ask.option_b.clone()
            } else {
                ask.option_a.clone()
            };
            match &ask.chosen {
                Some(previous) if *previous != chosen => {
                    return Err(invalid("an eval label ask was already answered otherwise"));
                }
                Some(_) => {
                    return case_in_txn(self, txn, case)?.ok_or(Error::EntityNotFound);
                }
                None => {}
            }
            ask.chosen = Some(chosen.clone());
            ask.answered_at = Some(at);
            self.store.vault_meta.put(txn, &key, &encode(&ask)?)?;
            append_label_in_txn(
                self,
                txn,
                case,
                EvalLabel {
                    kind: EvalLabelKind::OwnerPick,
                    value: chosen,
                    reference: ask.id.to_hex(),
                    weight: 1.0,
                    at,
                },
            )
        })
    }
}
