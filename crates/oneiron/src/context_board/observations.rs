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
        let (state, receipt) = lifecycle(read, id, kind, body)?;
        let Some(state) = state else {
            return Ok(receipt);
        };
        self.require_capacity(&id.to_hex())?;
        if loaded && kind == ENTITY_TYPE_SKILL {
            let skill = crate::skill::decode_skill_record(body)?;
            self.loaded_skill(id.to_hex(), skill.version);
        }
        self.served(id.to_hex(), state);
        Ok(receipt)
    }

    /// Record lifecycle metadata captured from an authorized, actually served row.
    pub fn observe_lifecycle(&mut self, id: EntityId, state: ServedLifecycle) -> Result<()> {
        self.require_capacity(&id.to_hex())?;
        self.served(id.to_hex(), state);
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
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let ScopedReadResult {
            value: rows,
            mut receipt,
        } = read.read(&reads, None)?;
        for row in rows.into_iter().flatten() {
            if let ReadRow {
                id,
                entity_type,
                body: Some(body),
                ..
            } = row
                && let Some(successor) =
                    self.observe_snapshot(read, id, entity_type, &body, false)?
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
        error.map_or(Ok(changed), Err)
    }
}

/// The served lifecycle, plus the successor read's receipt when one was made.
fn lifecycle(
    read: &ScopedRead<'_>,
    id: EntityId,
    kind: u8,
    body: &[u8],
) -> Result<(Option<ServedLifecycle>, Option<ScopedReadReceipt>)> {
    let state = match kind {
        ENTITY_TYPE_CLAIM => decode_claim_body(body, true)?.lifecycle,
        ENTITY_TYPE_SKILL => {
            return match match crate::skill::decode_skill_record(body) {
                Ok(record) => record.lifecycle_status,
                Err(_) => return Ok((None, None)),
            } {
                crate::skill::SkillLifecycle::Active => Ok((Some(ServedLifecycle::Active), None)),
                crate::skill::SkillLifecycle::Superseded => successor(read, id, kind),
                _ => Ok((None, None)),
            };
        }
        ENTITY_TYPE_AGENT_DEF => {
            let agent = crate::agent_def::decode_agent_definition(body)?;
            return Ok((
                Some(match agent.lifecycle_status {
                    ClaimLifecycleStatus::Active => ServedLifecycle::Active,
                    ClaimLifecycleStatus::Retracted => ServedLifecycle::Retracted,
                    ClaimLifecycleStatus::Superseded => return successor(read, id, kind),
                }),
                None,
            ));
        }
        _ => return Ok((None, None)),
    };
    match state {
        ClaimLifecycleStatus::Active => Ok((Some(ServedLifecycle::Active), None)),
        ClaimLifecycleStatus::Retracted => Ok((Some(ServedLifecycle::Retracted), None)),
        ClaimLifecycleStatus::Superseded => successor(read, id, kind),
    }
}

fn successor(
    read: &ScopedRead<'_>,
    id: EntityId,
    kind: u8,
) -> Result<(Option<ServedLifecycle>, Option<ScopedReadReceipt>)> {
    // Supersedes is directed new -> old. Do not follow to an unobserved chain head.
    // Only an unambiguous, currently readable successor can enter the response.
    let targets: Vec<_> = read
        .vault()
        .edges_in(&id)?
        .into_iter()
        .filter(|edge| edge.kind == crate::EdgeKind::Supersedes)
        .map(|edge| PointRead::id(edge.target))
        .collect();
    let ScopedReadResult {
        value: rows,
        receipt,
    } = read.read(&targets, None)?;
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
