//! A run's own skill pack load through its host door (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.pack.load`. The grant is the
//! caller's own attached run: its live attempt lease, checked in the load's
//! transaction, and the loadable check. No owner proof stands in for a run.
use crate::memory::MemoryResult;
use crate::task_verb::HostBinding;
use crate::{EntityId, Vault};

use super::skills::SkillLibraryFile;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skill_pack_load::{SkillPackLoadRequest, SkillPackLoaded};

/// Loads `input.skill` for the run `binding` seals, executing on
/// `executor`: the pack's exact files, stamped once on the attempt's
/// manifest in the load's own transaction. A skill that is not active and
/// approved, another resident's fork, or a lease that no longer holds
/// refuses, and stamps nothing. Beside the answer, the rows the pack's
/// instructions were read from.
pub fn skill_pack_load_on_live_run(
    vault: &Vault,
    binding: &HostBinding,
    executor: &str,
    input: &SkillPackLoadRequest,
) -> MemoryResult<(SkillPackLoaded, Vec<EntityId>)> {
    let at = vault.now_recorded_at();
    let (loaded, rows) = vault.load_bound_skill_pack(binding, &input.skill, executor, at)?;
    let files = loaded.source_files.map(|files| {
        files
            .into_iter()
            .map(|file| SkillLibraryFile {
                path: file.path,
                content: file.content,
            })
            .collect()
    });
    Ok((
        SkillPackLoaded {
            entity: loaded.entity,
            skill_id: loaded.record.skill_id,
            version: loaded.record.version,
            files,
        },
        rows,
    ))
}
