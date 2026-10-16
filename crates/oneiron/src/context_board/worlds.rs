//! WORLDS scope-map projection over the turn's resolved world authority.

use super::{BoardFrameError, BoardSection, SectionPolicy, ShedRank, one_line_token};
use crate::{
    EntityId,
    claim::ScopedRead,
    pipeline::{ResolvedWorldAuthority, WorldAuthoritySet},
    registry::ENTITY_TYPE_WORLD,
};
use std::collections::BTreeMap;

/// Display metadata from the world registry, not a source of authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldPresence {
    pub id: EntityId,
    pub label: String,
    pub trust: String,
}

impl WorldPresence {
    /// Display rows for the WORLD bodies `read` admits among `worlds`, in
    /// order. A world the caller cannot read, or an id that names no WORLD,
    /// yields no row, so it reaches neither the rows nor the counts. The
    /// label is the body's own `label` or `name` leaf when it carries one,
    /// else the id's short hex; trust is `foreign` for a received world's id
    /// range and `own` otherwise. Display only: authority is the fold's.
    pub fn read_admitted(
        read: &ScopedRead<'_>,
        worlds: &[EntityId],
    ) -> crate::Result<Vec<WorldPresence>> {
        let parts = read.get_entities_parts_with_receipt(worlds, None)?.value;
        Ok(worlds
            .iter()
            .zip(parts)
            .filter_map(|(id, parts)| {
                let (entity_type, _, body) = parts?;
                (entity_type == ENTITY_TYPE_WORLD).then(|| WorldPresence {
                    id: *id,
                    label: world_label(&body).unwrap_or_else(|| id.to_hex()[..8].to_owned()),
                    trust: if crate::entity_id::is_foreign_world_id_range(*id) {
                        "foreign"
                    } else {
                        "own"
                    }
                    .to_owned(),
                })
            })
            .collect())
    }
}

/// A WORLD body's display label: its `label` leaf, else its `name` leaf. A
/// body that is not a map, or that reads whole as a secret, has none.
fn world_label(body: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &body[..]).ok()?;
    if crate::batch::secret_scan::release_body_reads_whole_as_stored(&value, body) {
        return None;
    }
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    ["label", "name"].into_iter().find_map(|key| {
        entries
            .iter()
            .find(|(entry, _)| entry.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str())
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
    })
}

/// The board header's scope token for a resolved world set:
/// `WorldSet(base,<hex>,…)`, so the scope a board names is the scope its
/// planner resolved, never a caller string.
#[must_use]
pub fn world_set_scope(set: &WorldAuthoritySet) -> String {
    let members: Vec<String> = set
        .include_base()
        .then(|| "base".to_owned())
        .into_iter()
        .chain(set.worlds().iter().map(EntityId::to_hex))
        .collect();
    format!("WorldSet({})", members.join(","))
}

/// Allowed worlds only. Exclusion happens before rows or counts are computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldsSection {
    pub rows: Vec<String>,
    pub active_count: usize,
    pub off_count: usize,
}

impl WorldsSection {
    /// Projects the allowed-set roster. The off line is additive and bounded;
    /// overflow never accidentally counts an owner-excluded world.
    pub fn project(
        worlds: &[WorldPresence],
        authority: &ResolvedWorldAuthority,
        cap: usize,
    ) -> Self {
        let allowed: BTreeMap<_, _> = worlds
            .iter()
            .filter(|world| authority.allowed_set.worlds().contains(&world.id))
            .map(|world| (world.id, world))
            .collect();
        let (active, off): (Vec<&WorldPresence>, Vec<&WorldPresence>) = allowed
            .values()
            .copied()
            .partition(|world| authority.active_set.worlds().contains(&world.id));
        let mut active_rows: Vec<String> = active
            .iter()
            .map(|world| {
                format!(
                    "{} ACTIVE {} {}",
                    world.id.to_hex(),
                    one_line_token(&world.trust),
                    one_line_token(&world.label),
                )
            })
            .collect();
        let mut off_rows: Vec<String> = off
            .iter()
            .map(|world| {
                format!(
                    "{} AVAILABLE-OFF {}",
                    world.id.to_hex(),
                    one_line_token(&world.trust),
                )
            })
            .collect();
        // Base reality is part of ordinary authority, not a synthetic world id.
        // Exclusion removes it before both projection and counts.
        if authority.allowed_set.include_base() {
            if authority.active_set.include_base() {
                active_rows.insert(0, "base ACTIVE local".to_owned());
            } else {
                off_rows.insert(0, "base AVAILABLE-OFF local".to_owned());
            }
        }
        let active_count = active_rows.len();
        let off_count = off_rows.len();
        let mut rows: Vec<_> = active_rows.into_iter().take(cap).collect();
        if active_count > cap {
            rows.push(format!("active: +{}", active_count - cap));
        }
        if off_count > 0 {
            let mut line = format!(
                "off: {}",
                off_rows
                    .into_iter()
                    .take(cap)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if off_count > cap {
                line.push_str(&format!(" +{}", off_count - cap));
            }
            rows.push(line);
        }
        Self {
            rows,
            active_count,
            off_count,
        }
    }

    pub fn board_section(&self) -> Result<BoardSection, BoardFrameError> {
        let counts = vec![format!(
            "active: {} off: {}",
            self.active_count, self.off_count
        )];
        let mut detail = counts.clone();
        detail.extend(self.rows.iter().cloned());
        BoardSection::new(
            "WORLDS",
            Vec::new(),
            detail,
            counts,
            SectionPolicy {
                pinned: false,
                shed_rank: Some(ShedRank::WorldsToCounts),
            },
        )
    }
}
