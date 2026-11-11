//! Run admission and both-endpoint read checks precede the relation walk.

use std::collections::BTreeSet;

use super::*;
use crate::code_symbol::code_symbol_manifest_definitions;
use crate::memory::codebase_doors::{
    CodeSnapshotNeighborsRequest, check_neighbor_manifest, neighbor_view,
};

impl Memory<'_> {
    /// One-hop snapshot relations on readable paths and rows of the actual run.
    pub fn repo_symbols_neighbors_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSymbolsNeighborsInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSymbolsNeighborsOutput>> {
        let target = repo_target(input.repo, &input.git_ref, [input.path.as_str()]);
        let join = self.repo_read_join_for_run(
            binding,
            &target,
            None,
            &input.snapshot,
            super::read_join::SnapshotRows,
        )?;
        let admitted = join.admitted;
        let mount = join.mount;
        let artifact = mount.code_artifact_id();
        let manifest = self
            .vault
            .get_code_symbol_manifest(&artifact)?
            .ok_or_else(|| MemoryError::not_found("symbol manifest is absent"))?;
        check_neighbor_manifest(&manifest, &mount)?;
        let bounds = &admitted.membership.bounds;
        let candidates: Vec<_> = code_symbol_manifest_definitions(&manifest)?
            .into_iter()
            .filter(|definition| bounds.admits_path(RepoAccessIntent::Read, &definition.path))
            .collect();
        let ids = candidates
            .iter()
            .map(|definition| definition.entity_id)
            .collect();
        let readable: BTreeSet<_> = self.repo_lane_readable(binding, ids)?.into_iter().collect();
        let allowed = candidates
            .into_iter()
            .filter(|definition| {
                readable.contains(&definition.entity_id)
                    && mount.visible_file_entry(&definition.path).is_some()
            })
            .collect();
        let view = neighbor_view(
            &manifest,
            &mount,
            CodeSnapshotNeighborsRequest {
                repo: artifact,
                snapshot: input.snapshot,
                symbol: input.symbol,
                path: input.path,
                kinds: input.kinds,
                direction: input.direction,
            },
            allowed,
        )?;
        let mut rows = vec![input.repo, artifact, view.seed.definition.symbol];
        rows.extend(view.neighbors.iter().flat_map(|neighbor| {
            [
                neighbor.source.definition.symbol,
                neighbor.target.definition.symbol,
            ]
        }));
        Ok(RepoRunAnswer {
            rows,
            output: RepoSymbolsNeighborsOutput {
                repo: input.repo,
                git_ref: input.git_ref,
                snapshot: view.snapshot,
                seed: view.seed,
                neighbors: view.neighbors,
            },
        })
    }
}
