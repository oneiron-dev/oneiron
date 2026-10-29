//! FIX 3085: `vault.questions.refresh` on a standing artifact question asks
//! its artifacts by hand, now, beside the pump's due pass, never through it.
//!
//! Manual means now: no schedule, arrival or quiet interval is waited for,
//! and the refresh hold a failed pass set does not stop it. Every unit of
//! the selection is asked, as a schedule asks them. What still stops an
//! artifact is what stops the pump: a paused question asks nothing, an
//! artifact with no head or one its principal cannot read is not asked,
//! and an artifact whose earlier ask's proposal (or a wake's re-ask of it)
//! waits for Keep is never asked again until that settles. The ask is the
//! question's principal's, on its dial and clock, through the decider the
//! caller binds, the pump's own; model admission is the ask's own.

use std::time::Instant;

use super::super::refresh::standing_asker;
use super::super::saved_reader::{SavedArtifactReads, saved_artifact_reads};
use super::super::store::{QUESTION_VERSION, VersionKey, owned_head};
use super::{
    ASK_DEADLINE, ASKED, ArtifactAskRecord, Asking, Selection, artifact_ask_records, ask_selection,
    baseline,
};
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::edit_roundtrip::{ArtifactAsk, UnitDecider};
use crate::llm::decision::questions::{ARTIFACT_ADAPTER, ArtifactUnits, QuestionRecord};
use crate::llm::decision::{DecisionBandPolicy, Reversibility};
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// Asks the caller's standing artifact question `question` now, by hand, as
/// `principal`, under the class the question's version keeps (FIX 1588),
/// through the decider `decider_for` makes from its record and that actor,
/// under `policy`. `None` when the question's adapter is not
/// [`ARTIFACT_ADAPTER`], so the caller refreshes its graph units instead.
/// Else every ask it has made of its artifacts, this one included, as
/// [`artifact_ask_records`] lists them: empty for a paused question. Another
/// principal's question is not found.
pub fn refresh_artifact_question_now<D: UnitDecider>(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    now: u64,
    policy: &DecisionBandPolicy,
    decider_for: impl FnOnce(&QuestionRecord, WriteActor) -> Result<D>,
) -> Result<Option<Vec<ArtifactAskRecord>>> {
    let (version, record) = {
        let txn = vault.store.env.read_txn()?;
        let head = owned_head(vault, &txn, principal, question)?;
        let record = QUESTION_VERSION
            .get(
                &vault.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            .ok_or(Error::EntityNotFound)?;
        if record.definition.adapter != ARTIFACT_ADAPTER {
            return Ok(None);
        }
        if head.paused {
            return Ok(Some(Vec::new()));
        }
        (head.version, record)
    };
    let actor = standing_asker(vault, &record)?;
    let decider = decider_for(&record, actor)?;
    let asking = Asking {
        vault,
        question,
        version,
        record: &record,
        actor,
        policy,
        decider: &decider,
        now,
        quiet: 0,
    };
    for units in &record.definition.artifacts {
        asking.ask_now(units)?;
    }
    artifact_ask_records(vault, principal, question).map(Some)
}

impl Asking<'_> {
    /// Asks every unit of `units` now and holds the answers as a proposal,
    /// unless its artifact has no head, its principal cannot read it, or an
    /// earlier ask's proposal still waits for Keep. The ask is logged as the
    /// pump's are, a failed one too.
    fn ask_now(&self, units: &ArtifactUnits) -> Result<()> {
        let vault = self.vault;
        let artifact = units.artifact;
        let selection = Selection::resolve(&units.selection)?;
        let mut files = selection.files();
        let mut observed = Vec::with_capacity(files.len() + 1);
        let stamp = {
            let txn = vault.store.env.read_txn()?;
            for id in std::iter::once(&artifact).chain(&files) {
                let head = read_blob_artifact_head_in_txn(&vault.store, &txn, id)?;
                if *id == artifact && head.is_none() {
                    return Ok(());
                }
                observed.push((*id, head.map_or(0, |head| head.version)));
            }
            ASKED.get(&vault.store, &txn, &(self.question, artifact))?
        };
        // An unsettled proposal is never asked over, whichever version made it.
        if let Some(stamp) = &stamp
            && baseline(vault, artifact, stamp)?.is_none()
        {
            return Ok(());
        }
        // As the standing pump asks: inside the version's saved lane (FIX 2116).
        let principal = self.record.principal;
        let ids: Vec<EntityId> = std::iter::once(artifact)
            .chain(files.iter().copied())
            .collect();
        let SavedArtifactReads { readable, sight } =
            saved_artifact_reads(vault, principal, &self.record.read_lane, &ids)?;
        if !readable.contains(&artifact) {
            return Ok(());
        }
        files.retain(|file| readable.contains(file));
        let definition = &self.record.definition;
        // The recorded ceiling stands: a dial up to the person asks the next
        // authorised role for a unit, never stops at big (FIX 9912).
        let dial = definition.dial;
        let budget = definition.deadline(vault)?;
        self.ask_recorded(artifact, observed, "manual", |reference| {
            let ask = ArtifactAsk {
                question: &definition.question,
                principal,
                dial,
                policy: self.policy,
                reversibility: Reversibility::ReversibleRead,
                decider: self.decider,
                evidence: &[],
                budget,
                deadline: Instant::now() + ASK_DEADLINE,
                run_ref: reference,
            };
            ask_selection(vault, artifact, &selection, &files, None, ask, sight)
        })?;
        Ok(())
    }
}
