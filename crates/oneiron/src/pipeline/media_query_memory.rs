//! Retained storage of media queries copied into a native pipeline.

use std::ops::Deref;

use crate::embed::InputKind;
use crate::host_memory::{MachineMemory, MemoryLease};

use super::media_channel::MediaQuery;

#[derive(Default)]
pub(super) struct MediaQueries {
    queries: Vec<MediaQuery>,
    accounting: Option<(MachineMemory, MemoryLease)>,
}

impl MediaQueries {
    pub(super) fn bind_memory(&mut self, memory: &MachineMemory) {
        let mut lease = memory.empty_lease();
        lease.materialized(0, self.retained_bytes());
        self.accounting = Some((memory.clone(), lease));
    }

    pub(super) fn push(&mut self, query: MediaQuery) {
        let old_capacity = self.queries.capacity();
        let inner_bytes = query_bytes(&query);
        self.queries.push(query);
        let outer_growth = (self.queries.capacity().saturating_sub(old_capacity) as u64)
            .saturating_mul(std::mem::size_of::<MediaQuery>() as u64);
        if let Some((_, lease)) = self.accounting.as_mut() {
            lease.materialized(0, outer_growth.saturating_add(inner_bytes));
        }
    }

    fn retained_bytes(&self) -> u64 {
        self.queries.iter().fold(
            (self.queries.capacity() as u64)
                .saturating_mul(std::mem::size_of::<MediaQuery>() as u64),
            |bytes, query| bytes.saturating_add(query_bytes(query)),
        )
    }
}

impl Clone for MediaQueries {
    fn clone(&self) -> Self {
        let mut cloned = Self {
            queries: self.queries.clone(),
            accounting: None,
        };
        if let Some((memory, _)) = self.accounting.as_ref() {
            cloned.bind_memory(memory);
        }
        cloned
    }
}

impl Deref for MediaQueries {
    type Target = [MediaQuery];

    fn deref(&self) -> &Self::Target {
        self.queries.as_slice()
    }
}

impl<'a> IntoIterator for &'a MediaQueries {
    type Item = &'a MediaQuery;
    type IntoIter = std::slice::Iter<'a, MediaQuery>;

    fn into_iter(self) -> Self::IntoIter {
        self.queries.iter()
    }
}

fn query_bytes(query: &MediaQuery) -> u64 {
    (query.space_id.capacity() as u64)
        .saturating_add(
            (query.vector.capacity() as u64).saturating_mul(std::mem::size_of::<f32>() as u64),
        )
        .saturating_add(
            (query.kinds.capacity() as u64).saturating_mul(std::mem::size_of::<InputKind>() as u64),
        )
}

impl super::builder::PipelineBuilder<'_> {
    /// Account for copied media queries on the host's existing memory line.
    pub fn media_query_memory(mut self, memory: &MachineMemory) -> Self {
        self.media_search.bind_memory(memory);
        self
    }
}
