//! A question head's corpus (FIX 8237). The owner's adjudicated per-target
//! rows, one pinned version in the vault's custody, become the worker's
//! `oneiron.detector-target-row/1` training and held-out files. They are
//! split by the seat's source families, as the reservoir split is (OF-578),
//! and carry the split and consent receipts the trainer echoes. The owner's
//! authorization of the prepared spec decides consent: the receipts pin
//! what the run reads, and nothing here refuses a row for its consent.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::ModelLocality;
use crate::llm::run_admission::{PaidConnector, Payer};
use crate::skill_optimize::{EvalCohort, FamilyPurpose};

use super::custody::keep_bytes;
use super::{
    ArtifactPin, ComputeChoice, ComputePin, CorpusSplit, DetectorProvenance, QuestionTarget, RUNS,
    SplitRow, SplitSide, TrainingOwner, TrainingPackDraft, TrainingRun, TrainingState, hash_json,
    invalid,
};

/// The row format the worker reads, one JSON object per line.
const ROW_FORMAT: &str = "oneiron.detector-target-row/1";
/// A split receipt: this format, then the BLAKE3 of the cohort, the split
/// rows and both files' bytes.
const SPLIT_RECEIPT: &str = "oneiron.detector-split/1";
/// A consent receipt: this format, then the BLAKE3 of the owner's ticked
/// sources and each split row's consent basis and receipt.
const CONSENT_RECEIPT: &str = "oneiron.detector-consent/1";
/// The `excluded` count of rows whose source family feeds neither side: a
/// judge-audit family, or a sealed family outside the run's cohort.
const OUTSIDE_SPLIT: &str = "family_outside_split";
/// The one label unit a head trains on; a window label never becomes a
/// target label.
const TARGET_UNIT: &str = "target";

/// The prepared-corpus reference a question run is prepared from: the
/// owner's adjudicated per-target rows, one pinned version in custody. Each
/// line is a `oneiron.detector-target-row/1` row without its `format` and
/// `split`, and it names its `source` record instead of a `source_family`;
/// the ingress assigns the split and the family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorCorpusRef {
    pub rows: ArtifactPin,
}

/// One line of the owner's rows: an adjudicated label on one target of the
/// plan's exact question, the record it came from and the consent it was
/// taken under.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetRowInput {
    row: String,
    question_id: String,
    question_version: u32,
    corpus_revision: String,
    feature_schema: String,
    label_schema: String,
    /// A root of the seat's eval families: the record this target came from.
    source: String,
    consent: RowConsent,
    label: TargetLabel,
    input: TargetInput,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RowConsent {
    basis: String,
    receipt: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLabel {
    answer: TargetAnswer,
    unit: String,
    adjudication: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetAnswer {
    No,
    Yes,
}

/// The model's input: the exact target and its declared context.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetInput {
    target: Value,
    context: Vec<Value>,
}

/// One row as the worker reads it.
#[derive(Serialize)]
struct TargetRow<'a> {
    format: &'static str,
    row: &'a str,
    question_id: &'a str,
    question_version: u32,
    corpus_revision: &'a str,
    feature_schema: &'a str,
    label_schema: &'a str,
    split: SplitSide,
    source_family: String,
    consent: &'a RowConsent,
    label: &'a TargetLabel,
    input: &'a TargetInput,
}

impl TargetRowInput {
    fn check(&self, question: &QuestionTarget) -> Result<()> {
        let pins = self.question_id == question.question_id
            && self.question_version == question.question_version
            && self.corpus_revision == question.corpus_revision
            && self.feature_schema == question.feature_schema
            && self.label_schema == question.label_schema;
        let filled = [
            &self.row,
            &self.source,
            &self.consent.basis,
            &self.consent.receipt,
            &self.label.adjudication,
        ]
        .iter()
        .all(|text| !text.trim().is_empty());
        if !pins || !filled || self.label.unit != TARGET_UNIT || self.input.target.is_null() {
            return Err(invalid(&format!(
                "detector row {:?} needs the plan question's pins, a target-unit label with \
                 its adjudication, its consent, its source and a target",
                self.row
            )));
        }
        Ok(())
    }
}

impl DetectorCorpusRef {
    /// The validator: every line of the pinned rows parses as one row of
    /// `question` with a unique id.
    fn validate(&self, vault: &Vault, question: &QuestionTarget) -> Result<Vec<TargetRowInput>> {
        let body = vault.read_training_artifact(&self.rows)?;
        let mut ids = BTreeSet::new();
        let mut rows = Vec::new();
        for (index, line) in body.split(|byte| *byte == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let row: TargetRowInput = serde_json::from_slice(line).map_err(|error| {
                invalid(&format!("detector rows line {}: {error}", index + 1))
            })?;
            row.check(question)?;
            if !ids.insert(row.row.clone()) {
                return Err(invalid(&format!("detector row {:?} repeats", row.row)));
            }
            rows.push(row);
        }
        Ok(rows)
    }
}

/// The ingress's output: the worker's two files and what the split recorded.
struct DetectorSplit {
    training: Vec<u8>,
    held_out: Vec<u8>,
    rows: Vec<SplitRow>,
    overlaps: u64,
    excluded: BTreeMap<String, u64>,
    provenance: DetectorProvenance,
}

/// `format`, then the BLAKE3 of `covered`'s canonical JSON, as hex.
fn receipt(format: &str, covered: &impl Serialize) -> Result<String> {
    let digest = blake3::Hash::from(hash_json(covered)?);
    Ok(format!("{format}:{}", digest.to_hex()))
}

/// The detector-target-row/1 ingress: each row's source family decides its
/// side. A training family feeds training, the cohort's sealed families are
/// held out, and every other family is left out and counted.
fn split_rows(
    vault: &Vault,
    draft: &TrainingPackDraft,
    cohort: &EvalCohort,
    rows: &[TargetRowInput],
    consented: &[EntityId],
) -> Result<DetectorSplit> {
    let (mut training, mut held_out) = (Vec::new(), Vec::new());
    let (mut train_hashes, mut held_hashes) = (BTreeSet::new(), BTreeSet::new());
    let mut split = Vec::new();
    let mut excluded: BTreeMap<String, u64> = BTreeMap::new();
    let mut consents = Vec::new();
    let mut answers = BTreeSet::new();
    for row in rows {
        let family = vault
            .eval_family_of_root(&draft.plan.seat, &row.source)?
            .ok_or_else(|| {
                invalid("assign each detector row's source an eval family before splitting")
            })?;
        let side = match family.purpose {
            _ if vault.eval_family_feeds_training(&family.id)? => SplitSide::Training,
            FamilyPurpose::SealedConfirmation if cohort.families.contains(&family.id) => {
                SplitSide::HeldOut
            }
            _ => {
                *excluded.entry(OUTSIDE_SPLIT.to_owned()).or_insert(0) += 1;
                continue;
            }
        };
        let content = hash_json(&row.input)?;
        let line = serde_json::to_vec(&TargetRow {
            format: ROW_FORMAT,
            row: &row.row,
            question_id: &row.question_id,
            question_version: row.question_version,
            corpus_revision: &row.corpus_revision,
            feature_schema: &row.feature_schema,
            label_schema: &row.label_schema,
            split: side,
            source_family: family.id.to_hex(),
            consent: &row.consent,
            label: &row.label,
            input: &row.input,
        })
        .map_err(|_| invalid("a detector row does not encode"))?;
        let out = match side {
            SplitSide::Training => {
                train_hashes.insert(content);
                answers.insert(row.label.answer);
                &mut training
            }
            SplitSide::HeldOut => {
                held_hashes.insert(content);
                &mut held_out
            }
        };
        out.extend_from_slice(&line);
        out.push(b'\n');
        split.push(SplitRow {
            receipt: row.row.clone(),
            family: family.id,
            content_blake3: content,
            side,
        });
        consents.push((row.row.as_str(), &row.consent));
    }
    if training.is_empty() || held_out.is_empty() {
        return Err(invalid(
            "a training pack needs training and held-out rows in separate source families",
        ));
    }
    if answers.len() < 2 {
        return Err(invalid("a question head's training rows need both answers"));
    }
    consents.sort_unstable_by_key(|(row, _)| *row);
    let files = (
        *blake3::hash(&training).as_bytes(),
        *blake3::hash(&held_out).as_bytes(),
    );
    let provenance = DetectorProvenance {
        split_receipt: receipt(SPLIT_RECEIPT, &(&cohort.id, &split, files))?,
        consent_receipt: receipt(CONSENT_RECEIPT, &(consented, &consents))?,
    };
    Ok(DetectorSplit {
        overlaps: train_hashes.intersection(&held_hashes).count() as u64,
        training,
        held_out,
        rows: split,
        excluded,
        provenance,
    })
}

/// The run's compute, checked as [`Vault::prepare_training_pack`] checks it:
/// a named connector, a positive quantity, and off-owner compute only on the
/// run's explicit external choice.
fn compute_pin(draft: &TrainingPackDraft, connector: &PaidConnector) -> Result<ComputePin> {
    if draft.quantity == 0 || connector.connector.trim().is_empty() {
        return Err(invalid(
            "a training run needs a connector and a positive service quantity",
        ));
    }
    if draft.compute == ComputeChoice::OwnerMachines
        && (connector.locality == ModelLocality::ThirdParty || connector.payer == Payer::Host)
    {
        return Err(invalid(
            "off-owner compute needs an explicit external choice for this run",
        ));
    }
    Ok(ComputePin {
        choice: draft.compute,
        connector: connector.connector.clone(),
        adapter: connector.route.adapter().to_owned(),
        origin: connector.route.origin().to_owned(),
        locality: connector.locality,
        payer: connector.payer,
        binding_blake3: hash_json(connector)?,
        quantity: draft.quantity,
        unit_cost: connector.unit_cost,
        cost_unit: connector.cost_unit.clone(),
    })
}

impl Vault {
    /// The owner's run for one detector question's head (FIX 8237), the
    /// sibling of [`Vault::prepare_training_pack`]. The ingress reads the
    /// owner's rows at `corpus`, checks each against the plan's question,
    /// splits them by source family against the sealed cohort, and pins
    /// both files with their split and consent receipts. Nothing runs; the
    /// owner authorizes the spec.
    pub fn prepare_question_training_pack(
        &self,
        owner: &AuthenticatedOwner,
        draft: &TrainingPackDraft,
        corpus: &DetectorCorpusRef,
        connector: &PaidConnector,
    ) -> Result<TrainingRun> {
        self.recheck_owner(owner)?;
        let question = draft.plan.target.question().ok_or_else(|| {
            invalid("a role run trains on the consented reservoir, a question head on its rows")
        })?;
        draft.plan.validate()?;
        let compute = compute_pin(draft, connector)?;
        let cohort = self
            .eval_cohorts(&draft.plan.seat)?
            .into_iter()
            .find(|row| row.id == draft.split.held_out_cohort && row.retired_at.is_none())
            .ok_or_else(|| invalid("training split needs a live sealed cohort for its seat"))?;
        let mut consented = draft.consented_sources.clone();
        consented.sort_unstable();
        consented.dedup();
        let rows = corpus.validate(self, question)?;
        let split = split_rows(self, draft, &cohort, &rows, &consented)?;
        // The rows file, the pinned files and the held-out cohort's cases
        // and labels (FIX 5760); a lineage read that fails leaves them
        // unknown and never fails the run.
        let mut pinned = vec![corpus.rows.artifact];
        pinned.extend(
            draft
                .plan
                .starting_checkpoint
                .files
                .iter()
                .map(|file| file.content.artifact),
        );
        let source_rows = crate::skill_optimize::union_source_rows([
            Some(pinned),
            self.eval_cohort_source_rows(&cohort.id).ok().flatten(),
        ]);
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            draft.plan.starting_checkpoint.verify(self, txn)?;
            let id = self.store.clock.entity_id()?;
            let corpus_split = CorpusSplit {
                // A question run's export is the owner's rows file itself.
                export_receipt: corpus.rows.artifact,
                export: corpus.rows.clone(),
                training: keep_bytes(self, txn, actor, id, "training.jsonl", &split.training)?,
                held_out: keep_bytes(self, txn, actor, id, "held-out.jsonl", &split.held_out)?,
                cohort,
                rows: split.rows,
                exact_hash_overlaps: split.overlaps,
                consented_sources: consented,
                excluded: split.excluded,
                detector: Some(split.provenance),
            };
            let run = TrainingRun {
                id,
                owner: TrainingOwner::Actor(actor),
                created_at: self.store.clock.now_recorded_at(),
                spec_blake3: hash_json(&(&draft.plan, &compute, &corpus_split))?,
                plan: draft.plan.clone(),
                compute,
                corpus: corpus_split,
                state: TrainingState::Prepared,
                dispatch: None,
                result: None,
                evaluation: None,
                eval_exposure: None,
                authorization: None,
                hold: None,
                // A source an erase reached since the ingress read it does
                // not come back (FIX 6933).
                source_rows: crate::skill_optimize::live_source_rows_in(self, txn, source_rows)?,
            };
            RUNS.put(&self.store, txn, &id, &run)?;
            Ok(run)
        })
    }
}
