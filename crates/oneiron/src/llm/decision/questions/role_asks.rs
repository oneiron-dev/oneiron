//! A question unit's person ask (OF-506; ARCH-0076 role ladder): a graph or
//! artifact answer whose dial reaches the person asks the next authorised
//! role, under the caller's ceiling, ending at the vault's owners. The model
//! only requests the escalation; the caller binds the route, and the work the
//! ask decides is the unit's, so each unit keeps its own ask.
//!
//! A graph or artifact unit's ask is kept by its number while it waits (FIX
//! 11231), and the answer its role holder settles lands back on that unit as
//! the holder's own act: a `judgment.answer` claim whose receipt names the
//! ask, user-stated and approved from a person, generated and Auto from a
//! bound agent, as a settled conflict lands. An artifact unit (a sheet row, a
//! paragraph, a file in a folder) lands on its artifact, and its kept row
//! names the unit as the ask's caller named it. The model never grants
//! authority here: an abstention lands nothing, and an answer whose holder
//! was erased stays on the ask alone. No unit view carries ask numbers; the
//! kept rows are the read ([`Vault::question_unit_asks`]).

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::records::AnswerRecord;
use super::store::encode;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::llm::decision::{
    DecisionAnswer, DecisionQuestion, EvidenceVersion, HolderKind, TypedDecision,
};
use crate::side_table::{self, Named, SideTable};
use crate::{
    ClaimCandidate, EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor,
    WriteEnvelope, WriteProvenance,
};

const QUESTION_UNIT_ASK_DOMAIN: &[u8] = b"oneiron:question-unit-ask:v1";

/// Every graph or artifact unit's person ask, keyed by its arrival number.
const UNIT_ASKS: SideTable<u64, QuestionUnitAsk, Named> =
    SideTable::new(&side_table::TYPED_QUESTION_UNIT_ASK);

/// One unit's person ask: the unit (an artifact unit's artifact), the declined decision it
/// went up from (its receipt names the question, principal and ask) and, once its holder's
/// answer landed on the unit, that answer's claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionUnitAsk {
    /// The ask's arrival number.
    pub seq: u64,
    #[serde(with = "super::super::codec::entity")]
    pub unit: EntityId,
    /// The unit's source hash when it was asked.
    pub frontier: [u8; 32],
    pub source_kind: u8,
    /// The ladder's abstention that queued the ask, with its receipt.
    pub declined: TypedDecision,
    /// The `judgment.answer` claim the holder's answer landed as; none while the ask waits.
    #[serde(with = "super::super::codec::optional_entity")]
    pub applied: Option<EntityId>,
    /// The artifact unit the ask is for, as its caller named it (a sheet row, a paragraph,
    /// a folder file); none for a graph unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_unit: Option<serde_json::Value>,
}

/// The work one unit's ask decides: `question`'s version, asked for
/// `principal`, over `unit` at its `source` version. Two units, or one unit
/// at two versions, keep apart asks; the same unit at the same version asked
/// again on a refresh is the same open ask, so its recorded route and the
/// role it reached carry over.
pub fn question_unit_correlation(
    question: &DecisionQuestion,
    principal: EntityId,
    unit: &[u8],
    source: &[u8; 32],
) -> Result<EntityId> {
    EntityId::derive(
        QUESTION_UNIT_ASK_DOMAIN,
        &[
            question.id.as_bytes(),
            &question.version.to_le_bytes(),
            principal.as_bytes(),
            unit,
            source,
        ],
    )
}

/// [`keep_question_unit_ask`] for an artifact unit: `unit`, as its caller named it, of the
/// artifact version `pin` read (FIX 11231). Its answer lands on the artifact.
pub(crate) fn keep_artifact_unit_ask(
    vault: &Vault,
    pin: &EvidenceVersion,
    unit: &serde_json::Value,
    declined: &TypedDecision,
) {
    keep_question_unit_ask(
        vault,
        pin.id,
        pin.body_hash,
        crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
        Some(unit.clone()),
        declined,
    );
}

/// Keeps `unit`'s person ask, when its `declined` decision went up as a numbered one, and
/// lands an answer its holder already gave. Never a refusal: a row that does not keep
/// leaves the ask on its queue, answered there as before.
pub(super) fn keep_question_unit_ask(
    vault: &Vault,
    unit: EntityId,
    frontier: [u8; 32],
    source_kind: u8,
    artifact_unit: Option<serde_json::Value>,
    declined: &TypedDecision,
) {
    let Some(seq) = declined.receipt.asked.as_ref().and_then(|asked| asked.seq) else {
        return;
    };
    let kept = vault.with_write_txn_grouped(|txn| {
        if UNIT_ASKS
            .get(&vault.store, &*txn, &seq)?
            .is_some_and(|held| held.applied.is_some())
        {
            return Ok(());
        }
        UNIT_ASKS.put(
            &vault.store,
            txn,
            &seq,
            &QuestionUnitAsk {
                seq,
                unit,
                frontier,
                source_kind,
                declined: declined.clone(),
                applied: None,
                artifact_unit,
            },
        )
    });
    match kept {
        Ok(()) => vault.land_question_unit_answer(seq),
        Err(error) => {
            tracing::warn!(seq, kind = ?error.kind(), "a unit's person ask was not kept");
        }
    }
}

impl Vault {
    /// Lands the settled answer to unit ask `seq` on its unit, as its holder's own act, and
    /// returns the claim it landed as. `None` while the ask waits, for an abstention, for an
    /// answer whose holder was erased, and for an ask no unit kept. Landing twice returns
    /// the first claim.
    pub fn resume_question_unit_ask(&self, seq: u64) -> Result<Option<EntityId>> {
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let Some(mut row) = UNIT_ASKS.get(&self.store, &*txn, &seq)? else {
                return Ok(None);
            };
            if row.applied.is_some() {
                return Ok(row.applied);
            }
            let Some(ask) = self.decision_ask_in_txn(txn, seq)? else {
                return Ok(None);
            };
            let principal = row.declined.receipt.principal;
            if ask.question.id != row.declined.receipt.question
                || ask.question.version != row.declined.receipt.question_version
                || !ask.principal.is(principal)
            {
                return Err(Error::CorruptedIndex("question unit ask"));
            }
            let Some(held) = ask.answer.as_ref() else {
                return Ok(None);
            };
            let Some(by) = held.by.id().filter(|_| held.answer != DecisionAnswer::Abstain)
            else {
                return Ok(None);
            };
            let (class, source, approval) = match held.kind {
                HolderKind::Person => (
                    EdgeActorClass::Human,
                    ClaimSource::UserStated,
                    ClaimApprovalStatus::Approved,
                ),
                HolderKind::Agent => (
                    EdgeActorClass::Agent,
                    ClaimSource::Generated,
                    ClaimApprovalStatus::Auto,
                ),
            };
            let mut decision = row.declined.clone();
            decision.answer = held.answer.clone();
            decision.probability = None;
            decision.in_band = false;
            decision.receipt.bind_ask(&ask);
            let answer = AnswerRecord {
                claim: EntityId::now(),
                unit: row.unit,
                decision,
                frontier: row.frontier,
                source_kind: row.source_kind,
                answered_at: held.answered_at,
                omitted: Vec::new(),
            };
            let encoded = encode(&answer)?;
            let value = rmpv::decode::read_value(&mut encoded.as_slice())
                .map_err(|_| Error::CorruptedIndex("unit ask answer encoding"))?;
            let mut refs = vec![row.unit];
            for id in &answer.decision.evidence {
                if !refs.contains(id) {
                    refs.push(*id);
                }
            }
            let candidate = ClaimCandidate::new(
                "judgment.answer",
                ClaimSubject::Entity(row.unit),
                value.clone(),
                1.0,
            )
            .with_private_reader(principal)?
            .with_evidence(Value::Array(
                refs.iter().map(|id| Value::from(id.to_hex())).collect(),
            ));
            let envelope = WriteEnvelope::new(
                WriteActor::new(by, class),
                source,
                WriteProvenance::new(value)?,
                approval,
            );
            self.batch_in()
                .claim_candidate(
                    &answer.claim,
                    candidate,
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(txn)?;
            row.applied = Some(answer.claim);
            UNIT_ASKS.put(&self.store, txn, &seq, &row)?;
            Ok(row.applied)
        })
    }

    /// [`Self::resume_question_unit_ask`] once ask `seq`'s answer committed: the answer
    /// stands on its ask whatever lands, and a landing that failed is logged.
    pub(crate) fn land_question_unit_answer(&self, seq: u64) {
        if let Err(error) = self.resume_question_unit_ask(seq) {
            tracing::warn!(seq, kind = ?error.kind(), "a unit ask's answer did not land on its unit");
        }
    }

    /// The person asks kept on unit `unit`, a graph unit or an artifact, oldest first: each
    /// ask's number, the decision it went up from, the artifact unit it names, and the
    /// answer claim once one landed.
    pub fn question_unit_asks(&self, unit: EntityId) -> Result<Vec<QuestionUnitAsk>> {
        let txn = self.store.env.read_txn()?;
        let mut asks = Vec::new();
        for row in UNIT_ASKS.iter_from(&self.store, &txn, &[])? {
            let (_, ask) = row?;
            if ask.unit == unit {
                asks.push(ask);
            }
        }
        Ok(asks)
    }
}
