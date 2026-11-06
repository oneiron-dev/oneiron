//! One authenticated native-source open for a whole window reconstruction.

use std::collections::BTreeMap;
use std::sync::Arc;

use loro::checkpoint::{Atom, AtomId, Skeleton};

use super::reconstruct::{self, ReconstructionGroup, ReconstructionSource, SourceSite};
use super::{JoinedRecordDocument, OpenedRecordDocument};
use crate::error::Result;
use crate::store::checkpoint_payload::loro::Atom as ActorAtom;
use crate::store::checkpoint_payload::rows::bad_part;
use crate::sync::checkpoint_payload::{LoroSlice, OpenedSyncAtoms};
use crate::sync::skill_docs::checkpoint::RecordDocumentTransport;

struct OpenedSource {
    content: Vec<u8>,
    actors: Vec<ActorAtom>,
    transport: Arc<RecordDocumentTransport>,
}

#[derive(Default)]
struct OpenedSources(BTreeMap<SourceSite, OpenedSource>);

impl OpenedSources {
    fn open(
        &mut self,
        source: SourceSite,
        content: &[u8],
        actors: Vec<ActorAtom>,
    ) -> Result<Arc<RecordDocumentTransport>> {
        let mut actor_fields = actors.clone();
        actor_fields.sort_by(|left, right| left.field.cmp(&right.field));
        match self.0.entry(source) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                let transport = Arc::new(super::join(content, actors)?);
                entry.insert(OpenedSource {
                    content: content.to_vec(),
                    actors: actor_fields,
                    transport: Arc::clone(&transport),
                });
                Ok(transport)
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                let source = entry.get();
                if source.content != content || source.actors != actor_fields {
                    return Err(bad_part());
                }
                Ok(Arc::clone(&source.transport))
            }
        }
    }
}

/// One actual carrier join, before its native atoms have been reconstructed.
/// Ordinary atom availability comes from that same carrier's original join.
pub(crate) struct RecordDocumentRestoreGroup<'a> {
    pub(crate) skeleton: &'a Skeleton,
    pub(crate) sources: &'a [JoinedRecordDocument],
    pub(crate) available: Vec<Atom>,
    pub(crate) erased: Vec<AtomId>,
    pub(crate) slices: &'a [LoroSlice],
}

/// Opens each source's OWN authenticated copy and actor parts before any
/// reuse. A missing source still stays missing, even if another source or
/// group has a copy. Only equal opened content/actor fields of the SAME
/// original head share one native rejoin. The cache ends with this call.
pub(crate) fn reconstruct_window_opened(
    groups: Vec<RecordDocumentRestoreGroup<'_>>,
    opened: &dyn OpenedSyncAtoms,
) -> Result<Vec<reconstruct::ReconstructedWindow>> {
    let mut cache = OpenedSources::default();
    let mut transports: Vec<Vec<Option<OpenedRecordDocument>>> = Vec::with_capacity(groups.len());
    for group in &groups {
        super::super::frame::record_documents::validate(group.skeleton, group.sources)?;
        let mut group_transports = Vec::with_capacity(group.sources.len());
        for source in group.sources {
            let identity =
                reconstruct::source_site(group.skeleton, &source.entity_key, &source.slots)?;
            group_transports.push(source.open_using(opened, &mut |content, actors| {
                cache.open(identity.clone(), content, actors)
            })?);
        }
        transports.push(group_transports);
    }
    let mut reconstruction = Vec::with_capacity(groups.len());
    for (group, transports) in groups.into_iter().zip(&transports) {
        let sources = group
            .sources
            .iter()
            .zip(transports)
            .map(|(source, transport)| ReconstructionSource {
                entity_key: &source.entity_key,
                slots: &source.slots,
                opened: transport
                    .as_ref()
                    .map(|opened| (opened.transport.as_ref(), opened.lossless)),
            })
            .collect();
        reconstruction.push(ReconstructionGroup {
            skeleton: group.skeleton,
            sources,
            available: group.available,
            erased: group.erased,
            slices: group.slices,
        });
    }
    reconstruct::reconstruct_window(reconstruction)
}
