//! Read-time lifecycle observations over the same scoped bytes served to a session.

use super::{ChangedLine, ServedLifecycle, SessionReadSet};
use crate::claim::{
    ClaimLifecycleStatus, PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult,
    decode_claim_body,
};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};
use crate::{EntityId, Result};

impl SessionReadSet {
    /// Record an authorized body snapshot before its response is returned.
    /// `loaded` distinguishes a body from a discovery/metadata row.
    ///
    /// A superseded row is recorded with its successor only when that
    /// successor is readable; the successor read's receipt is returned so the
    /// caller can fold it into the response it is serving.
    pub fn observe_snapshot(
        &mut self,
        read: &ScopedRead<'_>,
        id: EntityId,
        kind: u8,
        body: &[u8],
        loaded: bool,
    ) -> Result<Option<ScopedReadReceipt>> {
        self.observe_snapshot_with_read_capacity(read, id, kind, body, loaded, &mut |_| {})
    }

    fn observe_snapshot_with_read_capacity<G>(
        &mut self,
        read: &ScopedRead<'_>,
        id: EntityId,
        kind: u8,
        body: &[u8],
        loaded: bool,
        observe: &mut impl FnMut(u64) -> G,
    ) -> Result<Option<ScopedReadReceipt>> {
        let (state, receipt) = lifecycle(read, id, kind, body, observe)?;
        let Some(state) = state else {
            return Ok(receipt);
        };
        if loaded && kind == ENTITY_TYPE_SKILL {
            let skill = crate::write_envelope::skill_record::decode_skill_record(body)?;
            self.loaded_skill(id.to_hex(), skill.version);
        }
        self.served(id.to_hex(), state);
        self.check_size(read.vault());
        Ok(receipt)
    }

    /// Record lifecycle metadata captured from an authorized, actually served
    /// row by `read`.
    pub fn observe_lifecycle(
        &mut self,
        read: &ScopedRead<'_>,
        id: EntityId,
        state: ServedLifecycle,
    ) -> Result<()> {
        self.served(id.to_hex(), state);
        self.check_size(read.vault());
        Ok(())
    }

    /// Record typed rows that survived the host's response projection. The
    /// rows are re-read in one snapshot; the returned receipt folds that read
    /// with every successor lookup it made.
    pub fn observe_rows(
        &mut self,
        read: &ScopedRead<'_>,
        ids: &[EntityId],
    ) -> Result<ScopedReadReceipt> {
        self.observe_rows_with_read_capacity(read, ids, |_| {})
    }

    /// Retain a holder for each temporary read buffer, including successor lookups.
    /// The observer returns a holder that drops after that buffer is consumed.
    pub fn observe_rows_with_read_capacity<G>(
        &mut self,
        read: &ScopedRead<'_>,
        ids: &[EntityId],
        mut observe: impl FnMut(u64) -> G,
    ) -> Result<ScopedReadReceipt> {
        let _reads_storage;
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        _reads_storage = observe(
            (reads.capacity() as u64).saturating_mul(std::mem::size_of::<PointRead<'_>>() as u64),
        );
        let _rows_storage;
        let ScopedReadResult {
            value: rows,
            mut receipt,
        } = read.read(&reads, None)?;
        _rows_storage = observe(observed_row_storage_bytes(&rows));
        for row in rows.into_iter().flatten() {
            if let ReadRow {
                id,
                entity_type,
                body: Some(body),
                ..
            } = row
                && let Some(successor) = self.observe_snapshot_with_read_capacity(
                    read,
                    id,
                    entity_type,
                    &body,
                    false,
                    &mut observe,
                )?
            {
                receipt.restrict_with(&successor);
            }
        }
        Ok(receipt)
    }

    /// Resolve changes when a board is read. This never emits a frame or notification.
    pub fn refresh(&self, read: &ScopedRead<'_>, cap: usize) -> Result<ChangedLine> {
        let mut error = None;
        let changed = self.changed(cap, |key| {
            let result = (|| {
                let id = EntityId::from_hex(key)?;
                read.read_set_lifecycle(&id)
            })();
            match result {
                Ok(state) => state,
                Err(cause) => {
                    error = Some(cause);
                    None
                }
            }
        });
        if let Some(error) = error {
            return Err(error);
        }
        let mut changed = changed;
        for receipt in read.vault().marketplace_install_receipts()? {
            let id = EntityId::from_hex(&receipt.entity)?;
            let crate::claim::ScopedReadResult { value, receipt: _ } =
                read.get_entity_parts_with_receipt(&id, None)?;
            if value.is_some_and(|(kind, _, _)| kind == ENTITY_TYPE_SKILL) {
                if changed.install_rows.len() < cap {
                    changed.install_rows.push(receipt);
                } else {
                    changed.install_overflow += 1;
                    changed.overflow_rows.push(receipt.entity);
                }
            }
        }
        Ok(changed)
    }
}

fn observed_row_storage_bytes(rows: &Vec<Option<ReadRow>>) -> u64 {
    let slots =
        (rows.capacity() as u64).saturating_mul(std::mem::size_of::<Option<ReadRow>>() as u64);
    rows.iter().flatten().fold(slots, |bytes, row| {
        bytes.saturating_add(row.body.as_ref().map_or(0, |body| body.capacity() as u64))
    })
}

/// The served lifecycle, plus the successor read's receipt when one was made.
fn lifecycle<G>(
    read: &ScopedRead<'_>,
    id: EntityId,
    kind: u8,
    body: &[u8],
    observe: &mut impl FnMut(u64) -> G,
) -> Result<(Option<ServedLifecycle>, Option<ScopedReadReceipt>)> {
    let state = match kind {
        ENTITY_TYPE_CLAIM => decode_claim_body(body, true)?.lifecycle,
        ENTITY_TYPE_SKILL => {
            return match match crate::write_envelope::skill_record::decode_skill_record(body) {
                Ok(record) => record.lifecycle_status,
                Err(_) => return Ok((None, None)),
            } {
                crate::write_envelope::skill_record::SkillLifecycle::Active => {
                    Ok((Some(ServedLifecycle::Active), None))
                }
                crate::write_envelope::skill_record::SkillLifecycle::Superseded => {
                    successor(read, id, kind, observe)
                }
                _ => Ok((None, None)),
            };
        }
        ENTITY_TYPE_AGENT_DEF => {
            let agent = crate::agent_def::decode_agent_definition(body)?;
            return Ok((
                Some(match agent.lifecycle_status {
                    ClaimLifecycleStatus::Active => ServedLifecycle::Active,
                    ClaimLifecycleStatus::Retracted => ServedLifecycle::Retracted,
                    ClaimLifecycleStatus::Superseded => return successor(read, id, kind, observe),
                }),
                None,
            ));
        }
        _ => return Ok((None, None)),
    };
    match state {
        ClaimLifecycleStatus::Active => Ok((Some(ServedLifecycle::Active), None)),
        ClaimLifecycleStatus::Retracted => Ok((Some(ServedLifecycle::Retracted), None)),
        ClaimLifecycleStatus::Superseded => successor(read, id, kind, observe),
    }
}

fn successor<G>(
    read: &ScopedRead<'_>,
    id: EntityId,
    kind: u8,
    observe: &mut impl FnMut(u64) -> G,
) -> Result<(Option<ServedLifecycle>, Option<ScopedReadReceipt>)> {
    // Supersedes is directed new -> old. Do not follow to an unobserved chain head.
    // Only an unambiguous, currently readable successor can enter the response.
    let _targets_storage;
    let targets: Vec<_> = {
        let _edges_storage;
        let edges = read.vault().edges_in(&id)?;
        _edges_storage = observe(edges.iter().fold(
            (edges.capacity() as u64).saturating_mul(std::mem::size_of::<crate::EdgeInfo>() as u64),
            |bytes, edge| {
                bytes.saturating_add(
                    edge.target_short_id
                        .as_ref()
                        .map_or(0, |short_id| short_id.capacity() as u64),
                )
            },
        ));
        edges
            .into_iter()
            .filter(|edge| edge.kind == crate::EdgeKind::Supersedes)
            .map(|edge| PointRead::id(edge.target))
            .collect()
    };
    _targets_storage = observe(
        (targets.capacity() as u64).saturating_mul(std::mem::size_of::<PointRead<'_>>() as u64),
    );
    let _rows_storage;
    let ScopedReadResult {
        value: rows,
        receipt,
    } = read.read(&targets, None)?;
    _rows_storage = observe(observed_row_storage_bytes(&rows));
    let mut next = None;
    for row in rows.into_iter().flatten() {
        if row.entity_type != kind {
            continue;
        }
        if next.replace(row.id).is_some() {
            return Ok((None, Some(receipt)));
        }
    }
    Ok((
        next.map(|next| ServedLifecycle::Superseded(next.to_hex())),
        Some(receipt),
    ))
}
