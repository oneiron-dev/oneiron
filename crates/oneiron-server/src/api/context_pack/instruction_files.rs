//! The instruction-file handles a context-pack response carries.

use std::collections::BTreeSet;

/// Keeps each instruction handle `pack` carries only over the units it still
/// returns, and only while `read` reads its CODE_ARTIFACT, all in one
/// snapshot (FIX 646): the handles are gathered before the scoped filter,
/// over units the caller may not be shown.
pub(super) fn project_instruction_files(
    read: &oneiron::claim::ScopedRead<'_>,
    pack: &mut oneiron::ContextPack,
) -> oneiron::Result<()> {
    let returned: BTreeSet<_> = pack
        .results
        .iter()
        .chain(&pack.neighbors)
        .map(|entity| entity.id)
        .collect();
    for handle in &mut pack.instruction_files {
        handle.units.retain(|unit| returned.contains(unit));
    }
    pack.instruction_files
        .retain(|handle| !handle.units.is_empty());
    let artifacts: Vec<_> = pack
        .instruction_files
        .iter()
        .map(|handle| vec![handle.code_artifact_id])
        .collect();
    let mut readable = read.refs_readable_each(&artifacts)?.into_iter();
    pack.instruction_files
        .retain(|_| readable.next().unwrap_or(false));
    Ok(())
}
