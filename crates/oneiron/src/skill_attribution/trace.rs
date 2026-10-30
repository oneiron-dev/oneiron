//! What the standing attribution classifier reads about one terminal attempt
//! (ARCH-0056 §5, ARCH-0066 T2): the actor its receipt is bound to, each skill
//! revision its pack loaded, and the attempt's own run. The host's model
//! judges how the attempt used each skill; this reader only gathers what the
//! vault recorded, and says `None` rather than guess a part it lacks.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::limit_ask::EngineLimit;
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_id};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill_optimize::union_source_rows;
use crate::{EntityId, Result, Vault};

use super::manifest_entry_names_skill;

/// SKILL entities one page reads while resolving the loaded revisions.
const SKILL_PAGE: usize = 256;

/// One skill revision an attempt's pack loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSkillRevision {
    /// The SKILL entity the pack loaded.
    pub skill: EntityId,
    /// Its manifest wire form, `skill_id@version`.
    pub revision: String,
    /// Its instructions.
    pub desc: String,
}

/// One terminal attempt as the attribution classifier reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptTrace {
    /// The actor the receipt is bound to.
    pub actor: EntityId,
    /// Each distinct revision the pack loaded, in manifest order. Empty when
    /// the manifest recorded no skills.
    pub skills: Vec<LoadedSkillRevision>,
    /// The attempt's kind, what it was asked when that is text, and its last
    /// error.
    pub kind: String,
    pub task: Option<String>,
    pub last_error: Option<String>,
    /// The run's host calls in order, each `effect request -> outcome`.
    pub steps: Vec<String>,
    /// The run's outputs, each `path: preview`.
    pub outputs: Vec<String>,
}

/// The trace one stamped attempt receipt grounds, every text whole: its
/// longest text and its count of steps and outputs are measured against
/// `limits.maintenance_text_bytes` and `limits.maintenance_row_items`, never
/// cut. `None` when a part is missing or ambiguous: no actor binding, no
/// recorded manifest, no attempt row, or a loaded revision that does not
/// resolve to exactly one SKILL record. A run with no record of its own
/// leaves the trace its attempt row.
pub fn receipt_attribution_trace(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<Option<ReceiptTrace>> {
    let Some(actor) = crate::skill::resident::receipt_resident(vault, &receipt.receipt_id)? else {
        return Ok(None);
    };
    let Some(manifest) = receipt.pack_manifest_skills() else {
        return Ok(None);
    };
    let mut wires = Vec::with_capacity(manifest.len());
    for wire in manifest {
        if !wires.contains(&wire) {
            wires.push(wire);
        }
    }
    let pinned = crate::skill::pinned_skill_revisions(vault, receipt)?;
    let Some(skills) = loaded_revisions(vault, &receipt.receipt_id, &actor, wires, pinned)? else {
        return Ok(None);
    };
    let Some(attempt) = receipt_attempt(&receipt.receipt_id) else {
        return Ok(None);
    };
    let Some(record) = AttemptQueue::new(vault).get(attempt)? else {
        return Ok(None);
    };
    // A run's id is its attempt's.
    let run = EntityId::from_bytes(*attempt.as_bytes())?;
    let mut steps = Vec::new();
    let mut outputs = Vec::new();
    if let Some(replay) = vault.get_code_run_replay_record(&run)? {
        for call in &replay.bridge_calls {
            let step = format!(
                "{} {} -> {}",
                call.effect.as_str(),
                call.request,
                call.outcome
            );
            steps.push(step);
        }
        for output in &replay.outputs {
            outputs.push(format!("{}: {}", output.path, output.preview.text));
        }
    }
    let trace = ReceiptTrace {
        actor,
        skills,
        kind: record.kind,
        task: std::str::from_utf8(&record.payload)
            .ok()
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned),
        last_error: record.last_error,
        steps,
        outputs,
    };
    // The classifier reads the run whole: its sizes are measured, never cut.
    let longest = trace
        .steps
        .iter()
        .chain(&trace.outputs)
        .chain(&trace.task)
        .chain(&trace.last_error)
        .map(String::len)
        .max()
        .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    let items = trace.steps.len() + trace.outputs.len();
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
    Ok(Some(trace))
}

/// [`receipt_attribution_trace`] beside the rows it was read from (FIX
/// 6997): the receipt's recorded attempt-input set, the run its attempt and
/// replay rows are keyed by, read whole, and each SKILL record it loaded.
/// The rows are `None`, unknown, when the receipt records no complete set.
pub fn receipt_attribution_trace_sourced(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<Option<(ReceiptTrace, Option<Vec<EntityId>>)>> {
    let Some(trace) = receipt_attribution_trace(vault, receipt)? else {
        return Ok(None);
    };
    let run = receipt_attempt(&receipt.receipt_id)
        .and_then(|attempt| EntityId::from_bytes(*attempt.as_bytes()).ok())
        .map(|run| vec![run]);
    let skills = trace.skills.iter().map(|skill| skill.skill).collect();
    let rows = union_source_rows([
        receipt.pack_source_rows(),
        run,
        Some(skills),
        Some(vec![trace.actor]),
    ]);
    Ok(Some((trace, rows)))
}

/// The SKILL record each wire names, at most one per wire. A wire the load
/// pinned resolves to the exact revision it read, even after an in-place
/// update (FIX 10110); only the others are matched against today's records.
/// A fork counts only as `actor`'s own; where a shared skill and a fork both
/// match, the one this receipt marked loaded wins.
fn loaded_revisions(
    vault: &Vault,
    receipt: &str,
    actor: &EntityId,
    wires: Vec<String>,
    pinned: Vec<(String, EntityId, crate::skill::SkillRecord)>,
) -> Result<Option<Vec<LoadedSkillRevision>>> {
    let mut matches: Vec<Vec<(EntityId, bool, String)>> = vec![Vec::new(); wires.len()];
    let mut by_pin = vec![false; wires.len()];
    for (wire, id, record) in pinned {
        let Some(at) = wires.iter().position(|held| *held == wire) else {
            continue;
        };
        let loaded = crate::skill::resident::receipt_loaded_skill(vault, receipt, &id)?;
        let fork_of = crate::skill::resident_of(&record)?;
        if fork_of.is_some() && (fork_of != Some(*actor) || !loaded) {
            continue;
        }
        by_pin[at] = true;
        if !matches[at].iter().any(|(held, _, _)| *held == id) {
            matches[at].push((id, loaded, record.desc));
        }
    }
    if by_pin.iter().any(|done| !done) {
        let mut after = None;
        loop {
            let page =
                vault.entities_by_type_page(ENTITY_TYPE_SKILL, after.as_ref(), SKILL_PAGE)?;
            for id in &page {
                let Some(record) = vault.get_skill_record(id)? else {
                    continue;
                };
                let named: Vec<_> = wires
                    .iter()
                    .enumerate()
                    .filter(|(at, wire)| !by_pin[*at] && manifest_entry_names_skill(wire, &record))
                    .map(|(at, _)| at)
                    .collect();
                if named.is_empty() {
                    continue;
                }
                let loaded = crate::skill::resident::receipt_loaded_skill(vault, receipt, id)?;
                let fork_of = crate::skill::resident_of(&record)?;
                if fork_of.is_some() && (fork_of != Some(*actor) || !loaded) {
                    continue;
                }
                for at in named {
                    matches[at].push((*id, loaded, record.desc.clone()));
                }
            }
            if page.len() < SKILL_PAGE {
                break;
            }
            after = page.last().copied();
        }
    }
    let mut skills: Vec<LoadedSkillRevision> = Vec::with_capacity(wires.len());
    for (revision, mut found) in wires.into_iter().zip(matches) {
        if found.len() > 1 {
            found.retain(|(_, loaded, _)| *loaded);
        }
        let mut found = found.into_iter();
        let (Some((skill, _, desc)), None) = (found.next(), found.next()) else {
            return Ok(None);
        };
        if skills.iter().any(|held| held.skill == skill) {
            return Ok(None);
        }
        skills.push(LoadedSkillRevision {
            skill,
            revision,
            desc,
        });
    }
    Ok(Some(skills))
}

/// The attempt a stamped receipt id names.
fn receipt_attempt(receipt: &str) -> Option<AttemptId> {
    let (_, hex) = receipt.rsplit_once(':')?;
    let attempt = AttemptId::from_bytes(EntityId::from_hex(hex).ok()?.as_bytes()).ok()?;
    (attempt_pack_receipt_id(&attempt) == receipt).then_some(attempt)
}
