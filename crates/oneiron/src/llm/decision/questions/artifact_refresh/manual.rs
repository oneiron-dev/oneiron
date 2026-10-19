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

use std::collections::BTreeSet;
use std::time::Instant;

use super::super::refresh::{principal_actor, source_actor_key};
use super::super::store::{QUESTION_VERSION, VersionKey, owned_head};
use super::{
    ASK_DEADLINE, ASKED, ArtifactAskRecord, ArtifactAsked, Asking, Selection, artifact_ask_records,
    ask_selection, baseline,
};
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::edit_roundtrip::{ArtifactAsk, UnitDecider};
use crate::llm::decision::questions::{ARTIFACT_ADAPTER, ArtifactUnits, QuestionRecord};
use crate::llm::decision::{DecisionBandPolicy, DecisionRung, Reversibility};
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// Asks the caller's standing artifact question `question` now, by hand, as
/// `principal`, through the decider `decider_for` makes from its record and
/// that actor, under `policy`. `None` when the question's adapter is not
/// [`ARTIFACT_ADAPTER`], so the caller refreshes its graph units instead.
/// Else every artifact it has asked, at its last ask, this one included:
/// empty for a paused question. Another principal's question is not found.
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
    let actor = principal_actor(vault, record.principal)?;
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
    /// earlier ask's proposal still waits for Keep.
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
        let principal = self.record.principal;
        let readable = {
            let txn = vault.store.env.read_txn()?;
            let key = source_actor_key(vault, &txn, principal, None)?
                .require_access_grants(Some(principal));
            let read = vault.scoped_read(key);
            let mut readable = BTreeSet::new();
            for id in std::iter::once(&artifact).chain(&files) {
                if read.entity_raw_live_in(&txn, id)?.is_some() {
                    readable.insert(*id);
                }
            }
            readable
        };
        if !readable.contains(&artifact) {
            return Ok(());
        }
        files.retain(|file| readable.contains(file));
        let reference = format!(
            "manual:{}:{}:{}",
            &self.question.to_hex()[..16],
            self.version,
            self.now
        );
        let definition = &self.record.definition;
        let mut dial = definition.dial;
        dial.ceiling = dial.ceiling.min(DecisionRung::Big);
        let ask = ArtifactAsk {
            question: &definition.question,
            principal,
            dial,
            policy: self.policy,
            reversibility: Reversibility::ReversibleRead,
            decider: self.decider,
            evidence: &[],
            budget: definition.deadline(vault)?,
            deadline: Instant::now() + ASK_DEADLINE,
            run_ref: &reference,
        };
        let run = ask_selection(vault, artifact, &selection, &files, None, ask)?;
        let proposed = match &run.proposal {
            Some(proposal) => {
                Some(vault.retain_edit_proposal(&artifact, proposal, None, self.actor, self.now)?)
            }
            None => None,
        };
        let stamp = ArtifactAsked {
            question_version: self.version,
            versions: observed,
            asked_at: self.now,
            proposal_ref: proposed.as_ref().map(|_| reference),
        };
        vault.with_write_txn(|wtxn| {
            ASKED.put(&vault.store, wtxn, &(self.question, artifact), &stamp)
        })
    }
}
