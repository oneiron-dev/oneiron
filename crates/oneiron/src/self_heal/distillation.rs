//! Owner-labeled T3 evidence -> T2 policy -> closed-form T1 proof.
//! No model grade, label, or mint operation signs or schedules a T1 run.
use super::{
    DiagnosticEvent, DiagnosticEventClass, DiagnosticObservation, DiagnosticSourceKind,
    decode_diagnostic_event_body,
    tiered::{DetectorPolicy, ProposedDiagnostic, TelemetryJudge},
    validate_diagnostic_event_admission, validate_token,
};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_DIAGNOSTIC;
use crate::side_table::{self, Named, SideTable};
use crate::store::{RetrievalRunId, RetrievalRunRecord};
use crate::{EntityId, Error, Result, Vault, consent::AuthenticatedOwner};
use serde::{Deserialize, Serialize};

const LABEL: SideTable<Vec<u8>, ReviewedFinding, Named> =
    SideTable::new(&side_table::SELF_HEAL_DISTILL);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedFinding {
    pub family: String,
    #[serde(with = "super::receipt_serde::id")]
    pub event_id: EntityId,
    #[serde(with = "super::receipt_serde::id")]
    pub reviewer: EntityId,
    pub positive: bool,
}

/// Minted model policy carries its exact reviewed examples. It has no T1 authority.
#[derive(Clone, Debug)]
pub struct MintedT2 {
    pub policy: DetectorPolicy,
    pub positive_events: Vec<EntityId>,
    pub negative_events: Vec<EntityId>,
}

/// Proof that a closed-form implementation reproduces the reviewed labels.
/// This does not provide an auto-arm method. A separately signed scheduled
/// detector run and the normal heal consent checks remain required.
#[derive(Clone, Debug)]
pub struct GraduatedT1 {
    pub predicate: ClosedFormPredicate,
    pub detector_id: &'static str,
    pub positive_events: Vec<EntityId>,
    pub negative_events: Vec<EntityId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosedFormPredicate {
    RetrievalMiss,
}

fn key(family: &str, id: &EntityId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(family.as_bytes());
    out.push(b':');
    out.extend_from_slice(id.as_bytes());
    out
}
fn family_prefix(family: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(family.as_bytes());
    out.push(b':');
    out
}

impl Vault {
    /// A corpus reference must be a live DIAGNOSTIC admitted at its real ID,
    /// not an arbitrary entity holding bytes copied from a diagnostic body.
    /// Envelope, visibility and body come from the same storage snapshot.
    pub(in crate::self_heal) fn reviewed_diagnostic(
        &self,
        id: &EntityId,
    ) -> Result<DiagnosticEvent> {
        let txn = self.store.env.read_txn()?;
        let row = self
            .store
            .port_entity_record(&txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let visibility = self.store.port_deletion_state(&txn, id)?;
        if row.entity_type != ENTITY_TYPE_DIAGNOSTIC
            || visibility.deleted
            || visibility.stale
            || visibility.archived
        {
            return Err(Error::InvalidConfig("not a live diagnostic entity".into()));
        }
        validate_diagnostic_event_admission(id, row.occurred, &row.body)?;
        decode_diagnostic_event_body(&row.body)
    }
    /// A model cannot label its own findings. Owner identity is reauthenticated
    /// and the cited event must be a stored T3 telemetry diagnostic.
    pub fn review_t3_finding(
        &self,
        owner: &AuthenticatedOwner,
        family: &str,
        event_id: EntityId,
        positive: bool,
    ) -> Result<ReviewedFinding> {
        validate_token(family, "distillation family is not a token")?;
        self.authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )?;
        let event = self.reviewed_diagnostic(&event_id)?;
        if event.source != DiagnosticSourceKind::RetrievalTelemetry
            || !event.detector_id.starts_with("t3.")
            || event.detector_id.strip_prefix("t3.") != Some(family)
        {
            return Err(Error::InvalidConfig(
                "label must cite matching T3 telemetry".into(),
            ));
        }
        let label = ReviewedFinding {
            family: family.into(),
            event_id,
            reviewer: owner.actor(),
            positive,
        };
        self.with_write_txn(|txn| {
            let k = key(family, &event_id);
            if let Some(stored) = LABEL
                .get(&self.store, txn, &k)
                .map_err(|_| Error::CorruptedIndex("distillation label"))?
            {
                if stored != label {
                    return Err(Error::InvalidConfig(
                        "label is immutable; review a new finding".into(),
                    ));
                }
                return Ok(stored);
            }
            LABEL.put(&self.store, txn, &k, &label)?;
            Ok(label)
        })
    }

    fn reviewed_findings(&self, family: &str) -> Result<Vec<ReviewedFinding>> {
        let txn = self.store.env.read_txn()?;
        let prefix = family_prefix(family);
        LABEL
            .iter_raw_from(&self.store, &txn, &prefix)?
            .map(|entry| {
                let (stored_key, raw) = entry?;
                let label = LABEL
                    .decode_value(&raw)
                    .map_err(|_| Error::CorruptedIndex("distillation label"))?;
                if label.family != family || stored_key != key(family, &label.event_id) {
                    return Err(Error::CorruptedIndex("distillation label key"));
                }
                Ok(label)
            })
            .collect()
    }

    /// Mint a T2 classifier after N distinct owner-reviewed T3 positives and
    /// at least one negative; an unlabeled recurring model opinion is not training.
    pub fn mint_t2(&self, policy: DetectorPolicy) -> Result<Option<MintedT2>> {
        policy.validate()?;
        let labels = self.reviewed_findings(&policy.family)?;
        let mut positive_events = Vec::new();
        let mut negative_events = Vec::new();
        for label in labels {
            let event = self.reviewed_diagnostic(&label.event_id)?;
            if event.event_class != policy.class
                || event.detector_id != format!("t3.{}", policy.family)
            {
                return Err(Error::InvalidConfig("T3 label class changed".into()));
            }
            if label.positive {
                positive_events.push(label.event_id);
            } else {
                negative_events.push(label.event_id);
            }
        }
        if positive_events.len() < policy.consecutive || negative_events.is_empty() {
            return Ok(None);
        }
        Ok(Some(MintedT2 {
            policy,
            positive_events,
            negative_events,
        }))
    }

    /// Execute the minted T2 with reviewed, vault-local examples supplied to
    /// the classifier. A stale or missing example fails closed before the call.
    pub fn classify_minted_t2(
        &self,
        minted: &MintedT2,
        judge: &impl TelemetryJudge,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        let Some(current) = self.mint_t2(minted.policy.clone())? else {
            return Err(Error::InvalidConfig(
                "T2 evidence is no longer sufficient".into(),
            ));
        };
        if current.positive_events != minted.positive_events
            || current.negative_events != minted.negative_events
        {
            return Err(Error::InvalidConfig("T2 examples changed".into()));
        }
        let mut examples = Vec::new();
        for (ids, positive) in [
            (&current.positive_events, true),
            (&current.negative_events, false),
        ] {
            for id in ids {
                let event = self.reviewed_diagnostic(id)?;
                let mut rows = Vec::new();
                for run_ref in &event.evidence_refs {
                    let row = self
                        .store
                        .retrieval_run(RetrievalRunId::from_bytes(*run_ref.as_bytes()))?
                        .ok_or(Error::EntityNotFound)?;
                    rows.push(row);
                }
                rows.sort_by_key(|row| (row.started_at, row.run_id.as_bytes()));
                if rows.is_empty() || !replays_group(&rows, &event)? {
                    return Err(Error::CorruptedIndex("T3 example telemetry changed"));
                }
                examples.push((rows, positive));
            }
        }
        self.classify_prompt_with_examples(&minted.policy, judge, runs, &examples)
    }

    /// Verify stored ARCH-0037 rows against a known closed-form detector.
    /// New dynamic predicates are not trusted as T1: they require a code change.
    pub fn graduate_t1(
        &self,
        minted: &MintedT2,
        predicate: ClosedFormPredicate,
    ) -> Result<Option<GraduatedT1>> {
        let (class, detector_id) = match predicate {
            ClosedFormPredicate::RetrievalMiss => {
                (DiagnosticEventClass::RetrievalMiss, "retrieval.miss.v1")
            }
        };
        if minted.policy.class != class {
            return Ok(None);
        }
        let current = self.mint_t2(minted.policy.clone())?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.positive_events != minted.positive_events
            || current.negative_events != minted.negative_events
        {
            return Err(Error::InvalidConfig("distillation evidence changed".into()));
        }
        for (ids, expected) in [
            (&current.positive_events, true),
            (&current.negative_events, false),
        ] {
            for id in ids {
                let event = self.reviewed_diagnostic(id)?;
                // A T3 window cannot be used as one T1 observation.
                if event.evidence_refs.len() != 1 {
                    return Ok(None);
                }
                let run_id = RetrievalRunId::from_bytes(*event.evidence_refs[0].as_bytes());
                let Some(run) = self.store.retrieval_run(run_id)? else {
                    return Ok(None);
                };
                if !replays(&run, &event)? {
                    return Ok(None);
                }
                let matches = match predicate {
                    ClosedFormPredicate::RetrievalMiss => {
                        DiagnosticObservation::from_retrieval_run(&run).is_some()
                    }
                };
                if matches != expected {
                    return Ok(None);
                }
            }
        }
        Ok(Some(GraduatedT1 {
            predicate,
            detector_id,
            positive_events: current.positive_events,
            negative_events: current.negative_events,
        }))
    }
}

fn replays_group(runs: &[RetrievalRunRecord], event: &super::DiagnosticEvent) -> Result<bool> {
    let mut hasher = blake3::Hasher::new();
    for run in runs {
        let bytes = rmp_serde::to_vec_named(run)
            .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(runs
        .last()
        .is_some_and(|last| event.replay.run_ref.as_deref() == Some(last.run_id.to_hex().as_str()))
        && event.replay.content_hash == *hasher.finalize().as_bytes())
}

fn replays(run: &RetrievalRunRecord, event: &super::DiagnosticEvent) -> Result<bool> {
    replays_group(std::slice::from_ref(run), event)
}
