//! WORLDS scope-map projection over the turn's resolved world authority.

use super::{BoardFrameError, BoardSection, SectionPolicy, ShedRank, one_line_token};
use crate::{EntityId, pipeline::ResolvedWorldAuthority};
use std::collections::BTreeMap;

/// Display metadata from the world registry, not a source of authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldPresence {
    pub id: EntityId,
    pub label: String,
    pub trust: String,
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
