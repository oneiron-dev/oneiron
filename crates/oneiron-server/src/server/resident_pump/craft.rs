//! A resident's own craft in its run's task (OF-490): every lesson and
//! failure mode it keeps, learned or approved by its owner, each loaded
//! through the resident's pack door, so the attempt's manifest names it.
//!
//! The task is part of the run's replay identity, so the section is frozen
//! per attempt once the run began, as a planned leader's pack is
//! (`pattern_launch`). Until its replay record exists an entry lists the
//! craft and loads each note the manifest does not name yet, in order, so an
//! entry cut between two loads takes the rest on its next entry; then the
//! section is the manifest's notes, in its order. Once the run began a
//! re-entry builds the same section from the manifest's rows and loads
//! nothing again, a run that had none included. A continuation's task, its
//! source's fork, holds its source's section already and takes nothing: the
//! notes its source run was shown are stamped on its own lease instead.
//!
//! A note whose every cited TURN was erased reads as erased here (FIX 8643):
//! a frozen section or a continued task holding one is not sent again.

use std::collections::BTreeSet;

use oneiron::actor_claims::{
    CRAFT_HEADING, craft_note_line, resident_craft_claim_ids, supported_craft_note,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ManifestKind};
use oneiron::engine_executor::EngineExecutorConfig;
use oneiron::engine_executor::continuation::run_continuation;
use oneiron::{EntityId, Error, Result, Vault, WriteActor};

use super::SKILL_SEPARATOR;

const ERASED: &str = "a craft note this run's task holds no longer reads, so its re-entry cannot \
     rebuild the task the run began with; run the agent afresh";
const CONTINUED_ERASED: &str = "a craft note this continuation's task holds no longer reads, so \
     the task cannot be sent again; run the agent afresh";
const NOT_A_NOTE: &str = "an actor claim this run loaded is no lesson or failure mode with a text \
     value, so its craft section cannot be built";

/// Appends `actor`'s craft to the task of its run on the leased try
/// `leased`, after the separator its skills take: the heading, then one line
/// per note, its kind and its whole text, in its manifest's order (newest
/// first as a first entry loads it). An entry before the run began reads
/// and loads what its manifest lacks at the pump's clock. Rule 5 caps none.
/// No craft appends nothing. A continuation stamps its source run's craft
/// on its own lease and appends nothing; a stamp that fails is logged and
/// the run goes on, as it did before it was stamped. Its support check fails
/// closed (FIX 8986): a read error there refuses the run, as an erased note
/// does.
///
/// # Errors
///
/// A load the resident's pack door refuses, a frozen or continued note that
/// no longer reads, and storage errors, a continuation's support check's
/// included.
pub(super) fn append_resident_craft(
    vault: &Vault,
    leased: &AttemptRecord,
    actor: WriteActor,
    config: &mut EngineExecutorConfig,
    continues: bool,
) -> Result<()> {
    let resident = actor.entity_ref();
    if continues {
        if !inherit_craft(vault, leased, &resident)? {
            return Err(refused(CONTINUED_ERASED));
        }
        return Ok(());
    }
    if vault.get_code_run_replay_record(&config.run_id)?.is_none() {
        // Not begun: what an entry cut between two loads left out loads now,
        // once each; what it loaded stays as it loaded.
        let loaded: BTreeSet<EntityId> = manifest_craft(vault, leased)?.into_iter().collect();
        let at = super::unix_now();
        for id in resident_craft_claim_ids(vault, &resident, at)? {
            if !loaded.contains(&id) {
                vault.load_resident_actor_claim(leased.id, &resident, &id, at)?;
            }
        }
    }
    let mut lines = vec![CRAFT_HEADING.to_owned()];
    for id in manifest_craft(vault, leased)? {
        let note = supported_craft_note(vault, &id)?.ok_or_else(|| refused(ERASED))?;
        lines.push(craft_note_line(&note).ok_or_else(|| refused(NOT_A_NOTE))?);
    }
    if lines.len() == 1 {
        return Ok(());
    }
    config.task.push_str(SKILL_SEPARATOR);
    config.task.push_str(&lines.join("\n"));
    Ok(())
}

/// Stamps the craft the run a continuation's checkpoint names was shown on
/// the continuation's own lease (OF-490), never the latest retry's. `false`,
/// stamping nothing, when a note that run was shown no longer reads (FIX
/// 8643): the continuation's task holds it. Every read up to that answer
/// fails closed with its own error (FIX 8986); only the stamp after it is
/// logged and passed over.
fn inherit_craft(vault: &Vault, leased: &AttemptRecord, resident: &EntityId) -> Result<bool> {
    let Some(continuation) = run_continuation(vault, leased.id)? else {
        return Ok(true);
    };
    let source = AttemptId::from_bytes(continuation.checkpoint.source_run.as_bytes())?;
    if !vault.attempt_craft_supported(source)? {
        return Ok(false);
    }
    if let Err(error) = vault.inherit_resident_craft(leased, source, resident, super::unix_now()) {
        tracing::warn!(kind = ?error.kind(), agent = %resident.to_hex(), "a continued run's craft was not stamped on its own attempt");
    }
    Ok(true)
}

/// The actor claims `leased`'s live manifest names, in its order.
fn manifest_craft(vault: &Vault, leased: &AttemptRecord) -> Result<Vec<EntityId>> {
    let live = AttemptQueue::new(vault)
        .get(leased.id)?
        .ok_or(Error::EntityNotFound)?;
    live.manifest()
        .iter()
        .filter(|entry| entry.kind == ManifestKind::ActorClaim)
        .map(|entry| EntityId::from_hex(&entry.reference))
        .collect()
}

/// Why a run cannot take its craft, and what to do next.
fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
