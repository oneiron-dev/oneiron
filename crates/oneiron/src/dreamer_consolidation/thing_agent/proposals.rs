//! The engine's own record of a thing's agent (FIX 7508): the host parent
//! run of each lease generation, the draft each extract staged there, the
//! checkpoint a cut run leaves, and the check of the refs the agent returns
//! against what was staged.
//!
//! A draft is staged by the engine, never by the agent: its candidates' ids
//! are the engine's own deterministic ids over the slice's durable step and
//! each candidate's place in its reply, and the step's memo keeps the whole
//! reply (its people, queries, citations and fallback mark) for the
//! per-slice path to replay.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::ThingProposalRef;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::code_run::{host_run_recorded, read_host_output, stage_host_output};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// The domain of a thing's host parent run.
const PARENT_RUN_DOMAIN: &[u8] = b"oneiron:dreamer-thing-parent:v1";

/// The domain of a staged draft candidate's id.
const DRAFT_ID_DOMAIN: &[u8] = b"oneiron:dreamer-thing-draft:v1";

/// Where a cut run's checkpoint sits in its parent run.
pub(super) const CHECKPOINT_PATH: &str = "thing/checkpoint.json";

/// Where a slice's staged draft sits in its parent run.
const DRAFT_ROOT: &str = "thing/draft/";

/// Each staged draft's path, with the candidate ids staged in it.
pub(super) type Issued = BTreeMap<String, BTreeSet<String>>;

/// The host parent run attempt `attempt` lends its agent under at lease
/// generation `generation`: a fresh transport run per generation, never a
/// reparented one.
pub(super) fn host_parent_run(attempt: AttemptId, generation: u32) -> Result<EntityId> {
    EntityId::derive(
        PARENT_RUN_DOMAIN,
        &[
            attempt.as_bytes().as_slice(),
            generation.to_be_bytes().as_slice(),
        ],
    )
}

/// The newest host parent run of `attempt` before `generation`, when one is
/// recorded: the attempt already ran as an agent.
pub(super) fn earlier_parent(
    vault: &Vault,
    attempt: AttemptId,
    generation: u32,
) -> Result<Option<EntityId>> {
    for earlier in (0..generation).rev() {
        let run = host_parent_run(attempt, earlier)?;
        if host_run_recorded(vault, run)? {
            return Ok(Some(run));
        }
    }
    Ok(None)
}

/// The newest checkpoint an earlier generation of `attempt` actually left,
/// before `generation` (FIX 9016): every earlier host parent run is read,
/// newest first, so a generation that ran and left none (its child settled,
/// or it was cut before it staged one) never hides an older one.
///
/// # Errors
///
/// The store's own errors.
pub(super) fn newest_checkpoint(
    vault: &Vault,
    attempt: AttemptId,
    generation: u32,
) -> Result<Option<Vec<u8>>> {
    for earlier in (0..generation).rev() {
        let run = host_parent_run(attempt, earlier)?;
        if let Some(checkpoint) = read_host_output(vault, run, CHECKPOINT_PATH)? {
            return Ok(Some(checkpoint));
        }
    }
    Ok(None)
}

/// What one extract staged for its slice.
pub(super) struct DraftFacts<'d> {
    pub(super) slice: usize,
    pub(super) input: &'d str,
    pub(super) step_hash: [u8; 32],
    pub(super) candidates: usize,
    pub(super) persons: usize,
    pub(super) fallback: bool,
}

/// A staged draft's body.
#[derive(Serialize)]
struct StagedDraft<'d> {
    slice: usize,
    input: &'d str,
    child_run: &'d str,
    step: String,
    candidates: &'d [String],
    persons: usize,
    fallback: bool,
}

/// Stages `facts`' draft in `parent_run` for `child_run`, notes its ids in
/// `issued`, and answers one ref for each of its candidates.
pub(super) fn stage_draft(
    vault: &Vault,
    parent_run: EntityId,
    child_run: EntityId,
    facts: &DraftFacts<'_>,
    issued: &mut Issued,
) -> Result<Vec<ThingProposalRef>> {
    let child_run = child_run.to_hex();
    let candidates = (0..facts.candidates)
        .map(|index| draft_candidate_id(&facts.step_hash, index).map(|id| id.to_hex()))
        .collect::<Result<Vec<_>>>()?;
    let path = format!("{DRAFT_ROOT}{}.json", facts.input);
    let body = serde_json::to_vec(&StagedDraft {
        slice: facts.slice,
        input: facts.input,
        child_run: &child_run,
        step: bytes_to_hex_lower(&facts.step_hash),
        candidates: &candidates,
        persons: facts.persons,
        fallback: facts.fallback,
    })
    .map_err(|_| Error::InvalidConfig("a staged thing draft did not encode".to_owned()))?;
    stage_host_output(vault, parent_run, path.clone(), &body)?;
    issued.insert(path.clone(), candidates.iter().cloned().collect());
    Ok(candidates
        .into_iter()
        .map(|candidate_id| ThingProposalRef {
            child_run: child_run.clone(),
            output_path: path.clone(),
            candidate_id,
        })
        .collect())
}

/// A cut run's checkpoint: what its slices' memos already hold.
#[derive(Serialize)]
struct ThingCheckpoint<'c> {
    generation: u32,
    child_run: String,
    extracted: &'c [String],
    decided: bool,
}

/// Stages the checkpoint of `child_run`'s pass in `parent_run`: the slice
/// inputs it extracted and whether it decided the pack. A later wake's run
/// is lent it as `checkpoint`.
pub(super) fn stage_checkpoint(
    vault: &Vault,
    parent_run: EntityId,
    generation: u32,
    child_run: EntityId,
    extracted: &[String],
    decided: bool,
) -> Result<()> {
    let body = serde_json::to_vec(&ThingCheckpoint {
        generation,
        child_run: child_run.to_hex(),
        extracted,
        decided,
    })
    .map_err(|_| Error::InvalidConfig("a thing checkpoint did not encode".to_owned()))?;
    stage_host_output(vault, parent_run, CHECKPOINT_PATH.to_owned(), &body).map(drop)
}

/// The refs a report returns; every other field is the agent's own.
#[derive(Deserialize, Default)]
#[serde(default)]
struct ThingChildReport {
    proposals: Vec<ThingProposalRef>,
}

/// How many refs `report` returns that name a draft the engine staged for
/// `child_run`, and how many name none. The engine's own record decides what
/// is assembled; a ref names no candidate into it.
pub(super) fn check_report(
    report: Option<&[u8]>,
    child_run: EntityId,
    issued: &Issued,
) -> (usize, usize) {
    let Some(report) =
        report.and_then(|bytes| serde_json::from_slice::<ThingChildReport>(bytes).ok())
    else {
        return (0, 0);
    };
    let child_run = child_run.to_hex();
    report
        .proposals
        .iter()
        .fold((0, 0), |(resolved, unresolved), proposal| {
            let staged = proposal.child_run == child_run
                && issued
                    .get(&proposal.output_path)
                    .is_some_and(|ids| ids.contains(&proposal.candidate_id));
            if staged {
                (resolved + 1, unresolved)
            } else {
                (resolved, unresolved + 1)
            }
        })
}

/// A staged candidate's engine id: its slice's step and its place in the
/// reply.
fn draft_candidate_id(step_hash: &[u8; 32], index: usize) -> Result<EntityId> {
    let index = u64::try_from(index).unwrap_or(u64::MAX);
    EntityId::derive(
        DRAFT_ID_DOMAIN,
        &[step_hash.as_slice(), index.to_be_bytes().as_slice()],
    )
}
