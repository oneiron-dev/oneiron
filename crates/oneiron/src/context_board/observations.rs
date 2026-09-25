//! Read-time lifecycle observations over the same scoped bytes served to a session.

use super::{ChangedLine, ServedLifecycle, SessionReadSet};
use crate::claim::{ClaimLifecycleStatus, ScopedRead, decode_claim_body};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};
use crate::{EntityId, Result};

impl SessionReadSet {
    /// Record an authorized body snapshot before its response is returned.
    /// `loaded` distinguishes a body from a discovery/metadata row.
    pub fn observe_snapshot(
        &mut self,
        read: &ScopedRead<'_>,
        id: EntityId,
        kind: u8,
        body: &[u8],
        loaded: bool,
    ) -> Result<()> {
        let Some(state) = lifecycle(read, id, kind, body)? else {
            return Ok(());
        };
        self.require_capacity(&id.to_hex())?;
        if loaded && kind == ENTITY_TYPE_SKILL {
            let skill = crate::skill::decode_skill_record(body)?;
            self.loaded_skill(id.to_hex(), skill.version);
        }
        self.served(id.to_hex(), state);
        Ok(())
    }

    /// Record lifecycle metadata captured from an authorized, actually served row.
    pub fn observe_lifecycle(&mut self, id: EntityId, state: ServedLifecycle) -> Result<()> {
        self.require_capacity(&id.to_hex())?;
        self.served(id.to_hex(), state);
        Ok(())
    }

    /// Record typed rows that survived the host's response projection.
    pub fn observe_rows(&mut self, read: &ScopedRead<'_>, ids: &[EntityId]) -> Result<()> {
        for id in ids {
            let crate::claim::ScopedReadResult {
                value,
                receipt: _receipt,
            } = read.get_entity_parts_with_receipt(id, None)?;
            if let Some((kind, _, body)) = value {
                self.observe_snapshot(read, *id, kind, &body, false)?;
            }
        }
        Ok(())
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

fn lifecycle(
    read: &ScopedRead<'_>,
    id: EntityId,
    kind: u8,
    body: &[u8],
) -> Result<Option<ServedLifecycle>> {
    let state = match kind {
        ENTITY_TYPE_CLAIM => decode_claim_body(body, true)?.lifecycle,
        ENTITY_TYPE_SKILL => {
            return match match crate::skill::decode_skill_record(body) {
                Ok(record) => record.lifecycle_status,
                Err(_) => return Ok(None),
            } {
                crate::skill::SkillLifecycle::Active => Ok(Some(ServedLifecycle::Active)),
                crate::skill::SkillLifecycle::Superseded => successor(read, id, kind),
                _ => Ok(None),
            };
        }
        ENTITY_TYPE_AGENT_DEF => {
            let agent = crate::agent_def::decode_agent_definition(body)?;
            return Ok(Some(match agent.lifecycle_status {
                ClaimLifecycleStatus::Active => ServedLifecycle::Active,
                ClaimLifecycleStatus::Retracted => ServedLifecycle::Retracted,
                ClaimLifecycleStatus::Superseded => return successor(read, id, kind),
            }));
        }
        _ => return Ok(None),
    };
    match state {
        ClaimLifecycleStatus::Active => Ok(Some(ServedLifecycle::Active)),
        ClaimLifecycleStatus::Retracted => Ok(Some(ServedLifecycle::Retracted)),
        ClaimLifecycleStatus::Superseded => successor(read, id, kind),
    }
}

fn successor(read: &ScopedRead<'_>, id: EntityId, kind: u8) -> Result<Option<ServedLifecycle>> {
    // Supersedes is directed new -> old. Do not follow to an unobserved chain head.
    // Only an unambiguous, currently readable successor can enter the response.
    let mut next = None;
    for edge in read.vault().edges_in(&id)? {
        if edge.kind != crate::EdgeKind::Supersedes {
            continue;
        }
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = read.get_entity_parts_with_receipt(&edge.target, None)?;
        let Some((next_kind, _, _)) = value else {
            continue;
        };
        if next_kind != kind {
            continue;
        }
        if next.replace(edge.target).is_some() {
            return Ok(None);
        }
    }
    Ok(next.map(|next| ServedLifecycle::Superseded(next.to_hex())))
}
