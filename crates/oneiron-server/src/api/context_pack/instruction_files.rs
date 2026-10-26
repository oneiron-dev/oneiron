//! The instruction-file handles a context-pack response carries.

/// The instruction handles for the units `pack` still returns, after its
/// last row filter and cut: resolved afresh under `read` and `disclosure`, in
/// one snapshot, each unit and its owning CODE_ARTIFACT admitted before any
/// of their metadata is read (FIX 646, FIX 9761). The handles assembly
/// gathered were read before the scoped filter and the JSON projection, over
/// units the caller may not be shown.
pub(super) fn returned_instruction_files(
    read: &oneiron::claim::ScopedRead<'_>,
    pack: &oneiron::ContextPack,
    disclosure: Option<&oneiron::disclosure::DisclosureContext>,
) -> oneiron::Result<Vec<oneiron::codebase::CodeInstructionHandle>> {
    let returned: Vec<_> = pack
        .results
        .iter()
        .chain(&pack.neighbors)
        .map(|entity| entity.id)
        .collect();
    read.context_pack_instruction_files_under(&returned, disclosure)
}
