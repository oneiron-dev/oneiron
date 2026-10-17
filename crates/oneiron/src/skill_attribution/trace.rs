//! What the standing attribution classifier reads about one terminal attempt
//! (ARCH-0056 §5, ARCH-0066 T2): the actor its receipt is bound to, each skill
//! revision its pack loaded, and the attempt's own run. The host's model
//! judges how the attempt used each skill; this reader only gathers what the
//! vault recorded, and says `None` rather than guess a part it lacks.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_id};
use crate::registry::ENTITY_TYPE_SKILL;
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
    /// Whether the byte budget cut the run: the earliest calls go first, so
    /// the step an attempt ended on stays.
    pub cut: bool,
}

/// The trace one stamped attempt receipt grounds. Each text is cut to
/// `item_bytes`, and the run's text to `trace_bytes` in all. `None` when a
/// part is missing or ambiguous: no actor binding, no recorded manifest, no
/// attempt row, or a loaded revision that does not resolve to exactly one
/// SKILL record. A run with no record of its own leaves the trace its
/// attempt row.
pub fn receipt_attribution_trace(
    vault: &Vault,
    receipt: &ReceiptRecord,
    trace_bytes: usize,
    item_bytes: usize,
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
    let Some(skills) = loaded_revisions(vault, &receipt.receipt_id, &actor, wires)? else {
        return Ok(None);
    };
    let Some(attempt) = receipt_attempt(&receipt.receipt_id) else {
        return Ok(None);
    };
    let Some(record) = AttemptQueue::new(vault).get(attempt)? else {
        return Ok(None);
    };
    let mut trace = ReceiptTrace {
        actor,
        skills,
        kind: record.kind,
        task: std::str::from_utf8(&record.payload)
            .ok()
            .filter(|text| !text.trim().is_empty())
            .map(|text| clip(text, item_bytes).to_owned()),
        last_error: record
            .last_error
            .map(|error| clip(&error, item_bytes).to_owned()),
        steps: Vec::new(),
        outputs: Vec::new(),
        cut: false,
    };
    // A run's id is its attempt's.
    let run = EntityId::from_bytes(*attempt.as_bytes())?;
    let Some(replay) = vault.get_code_run_replay_record(&run)? else {
        return Ok(Some(trace));
    };
    let mut left = trace_bytes;
    for call in replay.bridge_calls.iter().rev() {
        let text = format!(
            "{} {} -> {}",
            call.effect.as_str(),
            call.request,
            call.outcome
        );
        if !take(&mut trace.steps, &text, item_bytes, &mut left) {
            trace.cut = true;
            break;
        }
    }
    trace.steps.reverse();
    for output in &replay.outputs {
        let text = format!("{}: {}", output.path, output.preview.text);
        if !take(&mut trace.outputs, &text, item_bytes, &mut left) {
            trace.cut = true;
            break;
        }
    }
    Ok(Some(trace))
}

/// The SKILL record each wire names, at most one per wire. A fork counts only
/// as `actor`'s own; where a shared skill and a fork both match, the one this
/// receipt marked loaded wins.
fn loaded_revisions(
    vault: &Vault,
    receipt: &str,
    actor: &EntityId,
    wires: Vec<String>,
) -> Result<Option<Vec<LoadedSkillRevision>>> {
    let mut matches: Vec<Vec<(EntityId, bool, String)>> = vec![Vec::new(); wires.len()];
    if !wires.is_empty() {
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
                    .filter(|(_, wire)| manifest_entry_names_skill(wire, &record))
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

/// Keeps `text`, cut to `item_bytes`, while `left` has room for it.
fn take(into: &mut Vec<String>, text: &str, item_bytes: usize, left: &mut usize) -> bool {
    let text = clip(text, item_bytes.min(*left));
    if text.is_empty() {
        return false;
    }
    *left -= text.len();
    into.push(text.to_owned());
    true
}

/// At most `max` bytes of `text`, cut on a character boundary.
fn clip(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
