use super::*;

impl Memory<'_> {
    /// `vault.code.symbols.definitions`: the CALL behind the symbol door is
    /// exact-name Rust definitions only, as the ingest extractor records
    /// them in the pinned snapshot symbol manifest, in its stored order. No
    /// PPR score or Mentions edge is offered as a calls, imports or refs
    /// fact, and no other language is extracted for the caller.
    pub fn code_snapshot_definitions_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotDefinitionsRequest,
    ) -> MemoryResult<CodeSnapshotDefinitionsView> {
        self.codebase_owner(owner)?;
        let mount = self
            .codebase_pinned(input.repo, &input.snapshot)?
            .ok_or_else(|| MemoryError::not_found("code snapshot is absent or withheld"))?;
        if let Some(manifest) = self.vault.get_code_symbol_manifest(&input.repo)? {
            let pinned = mount.snapshot();
            if manifest.repo_ref != pinned.repo_ref || manifest.commit_hash != pinned.commit_hash {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the symbol manifest is not of the pinned snapshot",
                    &[],
                ));
            }
        }
        let found = self
            .vault
            .code_symbol_definitions(&input.repo, &input.name)?;
        self.produced_from(found.iter().map(|definition| definition.entity_id));
        let definitions = found
            .into_iter()
            .map(|definition| CodeSnapshotDefinition {
                symbol: definition.entity_id,
                path: definition.path,
                name: definition.name,
                kind: definition.kind,
                fingerprint: bytes_to_hex_lower(&definition.fingerprint),
                start_line: definition.start_line,
                end_line: definition.end_line,
            })
            .collect();
        Ok(CodeSnapshotDefinitionsView {
            repo: input.repo,
            snapshot: input.snapshot,
            definitions,
        })
    }
}
