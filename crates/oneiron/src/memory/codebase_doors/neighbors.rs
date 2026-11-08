//! One-hop relations read only after both endpoints enter the caller's allowed set.

use std::collections::BTreeMap;

use super::neighbor_types::{DEFAULT_CODE_RELATION_DIRECTION, DEFAULT_CODE_RELATION_KINDS};
use super::*;
use crate::code_symbol::{
    CodeSymbolDefinition, CodeSymbolManifest, code_symbol_manifest_definitions,
};

impl Memory<'_> {
    /// Recorded calls, imports and refs in one pinned snapshot, not shared-vault PPR.
    pub fn code_snapshot_neighbors_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotNeighborsRequest,
    ) -> MemoryResult<CodeSnapshotNeighborsView> {
        self.codebase_owner(owner)?;
        let mount = self
            .codebase_pinned(input.repo, &input.snapshot)?
            .ok_or_else(|| MemoryError::not_found("code snapshot is absent or withheld"))?;
        let manifest = self
            .vault
            .get_code_symbol_manifest(&input.repo)?
            .ok_or_else(|| MemoryError::not_found("symbol manifest is absent"))?;
        check_neighbor_manifest(&manifest, &mount)?;
        let mut allowed = Vec::new();
        for definition in code_symbol_manifest_definitions(&manifest)? {
            if self.codebase_readable(definition.entity_id)?
                && mount.visible_file_entry(&definition.path).is_some()
            {
                allowed.push(definition);
            }
        }
        let view = neighbor_view(&manifest, &mount, input, allowed)?;
        self.produced_from(std::iter::once(view.seed.definition.symbol).chain(
            view.neighbors.iter().flat_map(|neighbor| {
                [
                    neighbor.source.definition.symbol,
                    neighbor.target.definition.symbol,
                ]
            }),
        ));
        Ok(view)
    }
}

pub(crate) fn check_neighbor_manifest(
    manifest: &CodeSymbolManifest,
    mount: &CodebaseSnapshotMount<'_>,
) -> MemoryResult<()> {
    let pinned = mount.snapshot();
    if manifest.repo_ref != pinned.repo_ref || manifest.commit_hash != pinned.commit_hash {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the symbol manifest is not of the pinned snapshot",
            &[],
        ));
    }
    Ok(())
}

/// `allowed` was formed by the actual caller's native read checks before this
/// function sees a relation. The manifest and mount are the same pinned values.
pub(crate) fn neighbor_view(
    manifest: &CodeSymbolManifest,
    mount: &CodebaseSnapshotMount<'_>,
    input: CodeSnapshotNeighborsRequest,
    allowed: Vec<CodeSymbolDefinition>,
) -> MemoryResult<CodeSnapshotNeighborsView> {
    let allowed: BTreeMap<_, _> = allowed
        .into_iter()
        .map(|definition| (definition.entity_id, definition))
        .collect();
    let absent = || MemoryError::not_found("the symbol is absent or withheld in this snapshot");
    let seed = allowed
        .get(&input.symbol)
        .filter(|seed| seed.path == input.path)
        .ok_or_else(absent)?;
    let seed = cite_symbol(mount, seed)?;
    let kinds = input
        .kinds
        .as_deref()
        .unwrap_or(&DEFAULT_CODE_RELATION_KINDS);
    let direction = input.direction.unwrap_or(DEFAULT_CODE_RELATION_DIRECTION);
    let mut neighbors = Vec::new();
    for relation in &manifest.relations {
        // Construct the allowed subgraph before testing the seed or direction.
        let (Some(source), Some(target)) =
            (allowed.get(&relation.source), allowed.get(&relation.target))
        else {
            continue;
        };
        if !kinds.iter().any(|kind| kind.edge_kind() == relation.kind) {
            continue;
        }
        let outgoing = relation.source == input.symbol;
        let incoming = relation.target == input.symbol;
        let selected = match direction {
            CodeRelationDirection::In => incoming,
            CodeRelationDirection::Out => outgoing,
            CodeRelationDirection::Both => incoming || outgoing,
        };
        if selected {
            let kind = CodeRelationKind::from_edge(relation.kind).ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "unknown stored symbol relation",
                    &[],
                )
            })?;
            neighbors.push(CodeSnapshotNeighbor {
                kind,
                source: cite_symbol(mount, source)?,
                target: cite_symbol(mount, target)?,
            });
        }
    }
    Ok(CodeSnapshotNeighborsView {
        repo: input.repo,
        snapshot: input.snapshot,
        seed,
        neighbors,
    })
}

fn cite_symbol(
    mount: &CodebaseSnapshotMount<'_>,
    definition: &CodeSymbolDefinition,
) -> MemoryResult<CodeSnapshotSymbolCitation> {
    let file = mount.visible_file_entry(&definition.path).ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the symbol has no readable pinned file",
            &[],
        )
    })?;
    Ok(CodeSnapshotSymbolCitation {
        definition: CodeSnapshotDefinition {
            symbol: definition.entity_id,
            path: definition.path.clone(),
            name: definition.name.clone(),
            kind: definition.kind.clone(),
            fingerprint: bytes_to_hex_lower(&definition.fingerprint),
            start_line: definition.start_line,
            end_line: definition.end_line,
        },
        content_hash_blake3: bytes_to_hex_lower(&file.content_hash),
    })
}
