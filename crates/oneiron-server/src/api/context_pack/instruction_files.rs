//! The instruction-file handles a context-pack response carries.

/// Resolves the instruction handles `pack` carries afresh over the units it
/// still returns, after its last row filter and cut: under `read` and
/// `disclosure`, in one snapshot, each unit and its owning CODE_ARTIFACT
/// admitted before any of their metadata is read (FIX 646, FIX 9761). The
/// handles assembly gathered were read before the scoped filter, over units
/// the caller may not be shown.
pub(super) fn project_instruction_files(
    read: &oneiron::claim::ScopedRead<'_>,
    pack: &mut oneiron::ContextPack,
    disclosure: Option<&oneiron::disclosure::DisclosureContext>,
) -> oneiron::Result<()> {
    let returned: Vec<_> = pack
        .results
        .iter()
        .chain(&pack.neighbors)
        .map(|entity| entity.id)
        .collect();
    pack.instruction_files = read.context_pack_instruction_files_under(&returned, disclosure)?;
    Ok(())
}
