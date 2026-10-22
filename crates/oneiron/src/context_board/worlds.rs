//! WORLDS scope-map projection over the turn's resolved world authority.

use super::memories::MemoriesSection;
use super::{BoardFrameError, BoardSection, SectionPolicy, ShedRank, one_line_token};
use crate::{
    EntityId,
    claim::ScopedRead,
    pipeline::{ResolvedWorldAuthority, WorldAuthoritySet},
    registry::ENTITY_TYPE_WORLD,
};
use std::collections::{BTreeMap, BTreeSet};

/// Display metadata from the world registry, not a source of authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldPresence {
    pub id: EntityId,
    pub label: String,
    pub trust: String,
    /// The FICTION fence: the admitted WORLD's own `kind` names a reality
    /// other than `base` (fictional, dream, scenario or another kind).
    /// Engine-derived from the WORLD, never from a claim's text (ARCH-0002).
    pub fiction: bool,
}

impl WorldPresence {
    /// Display rows for the WORLD bodies `read` admits among `worlds`, in
    /// order. A world the caller cannot read, or an id that names no WORLD,
    /// yields no row, so it reaches neither the rows nor the counts. The
    /// label is the body's own `label` or `name` leaf when it carries one,
    /// else the id's short hex; trust is `foreign` for a received world's id
    /// range and `own` otherwise; `fiction` is the body's `kind` leaf naming
    /// anything but `base`. Display only: authority is the fold's.
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
                if entity_type != ENTITY_TYPE_WORLD {
                    return None;
                }
                let (label, kind) = world_leaves(&body);
                Some(WorldPresence {
                    id: *id,
                    label: label.unwrap_or_else(|| id.to_hex()[..8].to_owned()),
                    trust: if crate::entity_id::is_foreign_world_id_range(*id) {
                        "foreign"
                    } else {
                        "own"
                    }
                    .to_owned(),
                    fiction: kind.is_some_and(|kind| kind != "base"),
                })
            })
            .collect())
    }
}

impl MemoriesSection {
    /// Marks each row, and so its world's MEMORIES section, FICTION when the
    /// WORLD it sits in is one `read` admits and that WORLD's kind is not
    /// `base` (FIX 7756). The marker comes from the WORLD, so no row's text
    /// can strip or forge it; a world the read does not admit stays unmarked.
    pub fn fence_fiction_worlds(&mut self, read: &ScopedRead<'_>) -> crate::Result<()> {
        let worlds: BTreeSet<EntityId> = self
            .rows
            .iter()
            .filter_map(|row| EntityId::from_hex(row.world.as_deref()?).ok())
            .collect();
        if worlds.is_empty() {
            return Ok(());
        }
        let worlds: Vec<EntityId> = worlds.into_iter().collect();
        let fiction: BTreeSet<EntityId> = WorldPresence::read_admitted(read, &worlds)?
            .into_iter()
            .filter(|world| world.fiction)
            .map(|world| world.id)
            .collect();
        for row in &mut self.rows {
            row.fiction = row
                .world
                .as_deref()
                .and_then(|world| EntityId::from_hex(world).ok())
                .is_some_and(|world| fiction.contains(&world));
        }
        Ok(())
    }
}

/// The board's FICTION marker, with its leading space, for a row or section
/// whose WORLD is fenced; empty otherwise.
pub(super) fn fiction_marker(fiction: bool) -> &'static str {
    if fiction { " FICTION" } else { "" }
}

/// A WORLD body's display label (its `label` leaf, else its `name` leaf)
/// and its `kind` leaf. A body that is not a map, or that reads whole as a
/// secret, has neither.
fn world_leaves(body: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(value) = rmpv::decode::read_value(&mut &body[..]) else {
        return (None, None);
    };
    if crate::batch::secret_scan::release_body_reads_whole_as_stored(&value, body) {
        return (None, None);
    }
    let rmpv::Value::Map(entries) = value else {
        return (None, None);
    };
    let leaf = |key: &str| {
        entries
            .iter()
            .find(|(entry, _)| entry.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str())
            .map(str::trim)
            .filter(|leaf| !leaf.is_empty())
            .map(str::to_owned)
    };
    (leaf("label").or_else(|| leaf("name")), leaf("kind"))
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
                    "{} ACTIVE {}{} {}",
                    world.id.to_hex(),
                    one_line_token(&world.trust),
                    fiction_marker(world.fiction),
                    one_line_token(&world.label),
                )
            })
            .collect();
        let mut off_rows: Vec<String> = off
            .iter()
            .map(|world| {
                format!(
                    "{} AVAILABLE-OFF {}{}",
                    world.id.to_hex(),
                    one_line_token(&world.trust),
                    fiction_marker(world.fiction),
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
