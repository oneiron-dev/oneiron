//! A resident's own craft in its run's task (OF-490): every lesson and
//! failure mode it keeps, learned or approved by its owner, each loaded
//! through the resident's pack door, so the attempt's manifest names it.
//!
//! The task is part of the run's replay identity, so the section is frozen
//! per attempt, as a planned leader's pack is (`pattern_launch`). A first
//! entry lists the craft and loads each row, which stamps the manifest in
//! order. A re-entry, once those rows are stamped or the run has begun,
//! builds the same section from the manifest's rows and loads nothing again.
//! A continuation's task, its source's fork, holds its source's section
//! already and takes nothing.

use oneiron::actor_claims::{
    PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON, resident_craft_claim_ids,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ManifestKind};
use oneiron::claim::ClaimBody;
use oneiron::engine_executor::EngineExecutorConfig;
use oneiron::{EntityId, Error, Result, Vault, WriteActor};

use super::SKILL_SEPARATOR;

/// What heads the section; one line per note follows it.
const HEADING: &str = "Your craft notes (lessons and failure modes you keep):";
const ERASED: &str = "a craft note this run's task holds no longer reads, so its re-entry cannot \
     rebuild the task the run began with; run the agent afresh";
const NOT_A_NOTE: &str = "an actor claim this run loaded is no lesson or failure mode with a text \
     value, so its craft section cannot be built";

/// Appends `actor`'s craft to the task of its run on the leased try
/// `leased`, after the separator its skills take: the heading, then one line
/// per note, its kind and its whole text, newest first. A first entry reads
/// and loads it at the pump's clock. Rule 5 caps none. No craft appends
/// nothing.
///
/// # Errors
///
/// A load the resident's pack door refuses, a frozen note that no longer
/// reads, and storage errors.
pub(super) fn append_resident_craft(
    vault: &Vault,
    leased: &AttemptRecord,
    actor: WriteActor,
    config: &mut EngineExecutorConfig,
    continues: bool,
) -> Result<()> {
    if continues {
        return Ok(());
    }
    let resident = actor.entity_ref();
    let mut notes = Vec::new();
    match frozen_craft(vault, leased, &config.run_id)? {
        Some(frozen) => {
            for id in &frozen {
                notes.push(vault.get_claim(id)?.ok_or_else(|| refused(ERASED))?);
            }
        }
        None => {
            let at = super::unix_now();
            for id in resident_craft_claim_ids(vault, &resident, at)? {
                notes.push(vault.load_resident_actor_claim(leased.id, &resident, &id, at)?);
            }
        }
    }
    if notes.is_empty() {
        return Ok(());
    }
    let mut lines = vec![HEADING.to_owned()];
    for note in &notes {
        lines.push(note_line(note)?);
    }
    config.task.push_str(SKILL_SEPARATOR);
    config.task.push_str(&lines.join("\n"));
    Ok(())
}

/// The craft a re-entry of `leased`'s run `run` builds its section from: the
/// actor claims its manifest names, in order, once its first entry loaded
/// them or the run began (its replay record exists, as it does for a run that
/// had no craft). `None` for a first entry.
fn frozen_craft(
    vault: &Vault,
    leased: &AttemptRecord,
    run: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let live = AttemptQueue::new(vault)
        .get(leased.id)?
        .ok_or(Error::EntityNotFound)?;
    let mut frozen = Vec::new();
    for entry in live.manifest() {
        if entry.kind == ManifestKind::ActorClaim {
            frozen.push(EntityId::from_hex(&entry.reference)?);
        }
    }
    if frozen.is_empty() && vault.get_code_run_replay_record(run)?.is_none() {
        return Ok(None);
    }
    Ok(Some(frozen))
}

/// One note's line: its kind and its whole text.
fn note_line(note: &ClaimBody) -> Result<String> {
    let kind = match note.predicate.as_str() {
        PREDICATE_ACTOR_LESSON => "lesson",
        PREDICATE_ACTOR_FAILURE_MODE => "failure mode",
        _ => return Err(refused(NOT_A_NOTE)),
    };
    let text = note.value.as_str().ok_or_else(|| refused(NOT_A_NOTE))?;
    Ok(format!("- {kind}: {text}"))
}

/// Why a run cannot take its craft, and what to do next.
fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
