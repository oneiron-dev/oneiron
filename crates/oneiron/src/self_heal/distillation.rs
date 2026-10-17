//! Owner-labeled T3 evidence -> T2 policy -> closed-form T1 proof.
//! No model grade, label, or mint operation signs or schedules a T1 run.
//! The host's pass registers each family's minted T2 here (OF-418), and a
//! registration a shipped closed-form T1 reproduces is graduated: the T2
//! stops running and the T1 already runs in the Coach's tier-1 sweep.
use super::{
    DiagnosticEvent, DiagnosticEventClass, DiagnosticObservation, DiagnosticSourceKind,
    stored_diagnostic_event,
    tiered::{DetectorDecisions, DetectorPolicy, ProposedDiagnostic},
    validate_token,
};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_DIAGNOSTIC;
use crate::side_table::{self, Named, SideTable};
use crate::store::{RetrievalRunId, RetrievalRunRecord};
use crate::{EntityId, Error, Result, Vault, consent::AuthenticatedOwner};
use serde::{Deserialize, Serialize};

const LABEL: SideTable<Vec<u8>, ReviewedFinding, Named> =
    SideTable::new(&side_table::SELF_HEAL_DISTILL);
/// Each family's registered T2. Key: the family.
const MINTED: SideTable<Vec<u8>, MintedRegistration, Named> =
    SideTable::new(&side_table::SELF_HEAL_MINTED);

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

/// One family's registered T2: the exact reviewed corpus the host's pass asks
/// with, and the closed-form T1 that retired it, if one reproduces every label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintedRegistration {
    pub family: String,
    /// Hash of the seed's wording and the corpus. A new label or a reworded
    /// seed is a new revision, registered afresh.
    pub revision: [u8; 32],
    #[serde(with = "super::receipt_serde::ids")]
    pub positive_events: Vec<EntityId>,
    #[serde(with = "super::receipt_serde::ids")]
    pub negative_events: Vec<EntityId>,
    pub registered_at: u64,
    /// The T1 detector that reproduces this revision's labels. A graduated
    /// T2 no longer runs.
    pub graduated_to: Option<String>,
}

/// One reviewed example as a minted T2 is shown it: its runs, oldest first.
#[derive(Clone, Debug)]
pub struct MintedExample {
    pub event_id: EntityId,
    pub positive: bool,
    pub runs: Vec<RetrievalRunRecord>,
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
impl ClosedFormPredicate {
    /// The shipped closed-form detector that raises `class`. A class with none
    /// cannot graduate until a release ships one.
    #[must_use]
    pub fn for_class(class: DiagnosticEventClass) -> Option<Self> {
        match class {
            DiagnosticEventClass::RetrievalMiss => Some(Self::RetrievalMiss),
            _ => None,
        }
    }

    /// Whether this closed form raises on a reviewed window: on any one of its
    /// runs, as the T1 raises per run. The policy hook for how a T3 window's
    /// label reads as T1 evidence.
    fn raises_on(self, runs: &[RetrievalRunRecord]) -> bool {
        runs.iter().any(|run| match self {
            Self::RetrievalMiss => DiagnosticObservation::from_retrieval_run(run).is_some(),
        })
    }
}

fn key(family: &str, id: &EntityId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(family.as_bytes());
    out.push(b':');
    out.extend_from_slice(id.as_bytes());
    out
}
/// A registration's revision: the seed's wording and the exact corpus.
fn minted_revision(minted: &MintedT2) -> [u8; 32] {
    let policy = &minted.policy;
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.self_heal.minted_t2.v1\0");
    for part in [
        policy.family.as_str(),
        policy.class.as_str(),
        policy.prompt.as_str(),
        policy.rubric.as_str(),
    ] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(&(policy.consecutive as u64).to_be_bytes());
    for ids in [&minted.positive_events, &minted.negative_events] {
        hash.update(&(ids.len() as u64).to_be_bytes());
        for id in ids {
            hash.update(id.as_bytes());
        }
    }
    *hash.finalize().as_bytes()
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
        stored_diagnostic_event(id, row.occurred, &row.body)
    }
    /// A model cannot label its own findings. The owner proof is rechecked in
    /// the transaction that writes the label, and the cited event must be a
    /// stored T3 telemetry diagnostic.
    pub fn review_t3_finding(
        &self,
        owner: &AuthenticatedOwner,
        family: &str,
        event_id: EntityId,
        positive: bool,
    ) -> Result<ReviewedFinding> {
        validate_token(family, "distillation family is not a token")?;
        let event = self.reviewed_diagnostic(&event_id)?;
        if event.source != DiagnosticSourceKind::RetrievalTelemetry
            || !event.detector_id.starts_with("t3.")
            || event.detector_id.strip_prefix("t3.") != Some(family)
        {
            return Err(Error::InvalidConfig(
                "label must cite matching T3 telemetry".into(),
            ));
        }
        self.with_write_txn_grouped(|txn| {
            let label = ReviewedFinding {
                family: family.into(),
                event_id,
                reviewer: owner.revalidate_in_txn(self, &*txn)?,
                positive,
            };
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

    /// The owner's label on one raised finding, if any.
    pub(super) fn t3_label(&self, family: &str, event_id: &EntityId) -> Result<Option<bool>> {
        let txn = self.store.env.read_txn()?;
        Ok(LABEL
            .get(&self.store, &txn, &key(family, event_id))
            .map_err(|_| Error::CorruptedIndex("distillation label"))?
            .map(|label| label.positive))
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
        decisions: &DetectorDecisions<'_>,
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
        self.minted_t2_examples(&current)?;
        self.classify_prompt_with_examples(
            &minted.policy,
            decisions,
            runs,
            (&current.positive_events, &current.negative_events),
        )
    }

    /// Each reviewed example's runs, positives first: what the host shows a
    /// minted T2 beside the runs it grades. A run gone or changed since its
    /// finding was raised fails closed, as the classifier does.
    pub fn minted_t2_examples(&self, minted: &MintedT2) -> Result<Vec<MintedExample>> {
        let mut examples = Vec::new();
        for (ids, positive) in [
            (&minted.positive_events, true),
            (&minted.negative_events, false),
        ] {
            for id in ids {
                let runs = self
                    .example_runs(id)?
                    .ok_or(Error::CorruptedIndex("T3 example telemetry changed"))?;
                examples.push(MintedExample {
                    event_id: *id,
                    positive,
                    runs,
                });
            }
        }
        Ok(examples)
    }

    /// A reviewed finding's runs, oldest first, while they still replay to
    /// its hash; `None` when one is gone or changed.
    fn example_runs(&self, id: &EntityId) -> Result<Option<Vec<RetrievalRunRecord>>> {
        let event = self.reviewed_diagnostic(id)?;
        let mut rows = Vec::with_capacity(event.evidence_refs.len());
        for run_ref in &event.evidence_refs {
            let Some(row) = self
                .store
                .retrieval_run(RetrievalRunId::from_bytes(*run_ref.as_bytes()))?
            else {
                return Ok(None);
            };
            rows.push(row);
        }
        rows.sort_by_key(|row| (row.started_at, row.run_id.as_bytes()));
        Ok((!rows.is_empty() && replays_group(&rows, &event)?).then_some(rows))
    }

    /// Registers the T2 a seed `t3` policy's reviewed findings mint, or keeps
    /// the registration the same wording and corpus already hold. A new
    /// revision is checked once against the shipped closed-form T1 for its
    /// class; one that reproduces every label is graduated and stops running.
    /// `None` until the reviewed findings mint a T2.
    pub fn register_minted_t2(
        &self,
        seed: &DetectorPolicy,
        now: u64,
    ) -> Result<Option<(MintedT2, MintedRegistration)>> {
        let Some(minted) = self.mint_t2(seed.clone())? else {
            return Ok(None);
        };
        let revision = minted_revision(&minted);
        let k = seed.family.as_bytes().to_vec();
        let stored = {
            let txn = self.store.env.read_txn()?;
            MINTED
                .get(&self.store, &txn, &k)
                .map_err(|_| Error::CorruptedIndex("minted detector"))?
        };
        if let Some(stored) = stored.filter(|stored| stored.revision == revision) {
            return Ok(Some((minted, stored)));
        }
        let graduated_to = match ClosedFormPredicate::for_class(seed.class) {
            Some(predicate) => self
                .graduate_t1(&minted, predicate)?
                .map(|t1| t1.detector_id.to_owned()),
            None => None,
        };
        let registration = MintedRegistration {
            family: seed.family.clone(),
            revision,
            positive_events: minted.positive_events.clone(),
            negative_events: minted.negative_events.clone(),
            registered_at: now,
            graduated_to,
        };
        self.with_write_txn_grouped(|txn| MINTED.put(&self.store, txn, &k, &registration))?;
        Ok(Some((minted, registration)))
    }

    /// Every family's registered T2, by family: the owner's read.
    pub fn minted_registrations(&self) -> Result<Vec<MintedRegistration>> {
        let txn = self.store.env.read_txn()?;
        MINTED
            .iter_from(&self.store, &txn, &[])?
            .map(|row| row.map(|(_, registration)| registration))
            .collect()
    }

    /// Verify stored ARCH-0037 rows against a known closed-form detector.
    /// New dynamic predicates are not trusted as T1: they require a code change.
    /// A reviewed window agrees when the closed form raises on one of its runs
    /// exactly when the owner confirmed it.
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
                let Some(runs) = self.example_runs(id)? else {
                    return Ok(None);
                };
                if predicate.raises_on(&runs) != expected {
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
