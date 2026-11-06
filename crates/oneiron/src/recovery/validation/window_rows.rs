//! Window row validation with owned indexes and a cursor between admitted turns.

use super::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, id, invalid, trusted_soft_addressing_edge,
};
use crate::deletion::DecodedTombstoneValue;
use crate::error::Result;
use crate::recovery::canonical::{
    CanonicalBaseEdge, CanonicalEntity, CanonicalShellWorld, CanonicalSnapshot, CanonicalTombstone,
};
use std::collections::BTreeMap;

#[derive(Default)]
pub(in crate::recovery) struct WindowRows {
    stage: Stage,
    next: usize,
    world: Option<crate::EntityId>,
    deleted: BTreeMap<[u8; 16], DecodedTombstoneValue>,
    shell_worlds: BTreeMap<[u8; 16], [u8; 16]>,
}

#[derive(Default)]
enum Stage {
    #[default]
    World,
    DeletedIndex,
    ShellWorldIndex,
    Shells,
    Entities,
    Edges,
    Tombstones,
    Complete,
}

impl WindowRows {
    pub(in crate::recovery) fn advance(
        &mut self,
        snapshot: &CanonicalSnapshot,
        max_rows: usize,
    ) -> Result<bool> {
        for _ in 0..max_rows.max(1) {
            if self.advance_row(snapshot)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn advance_row(&mut self, snapshot: &CanonicalSnapshot) -> Result<bool> {
        loop {
            match self.stage {
                Stage::World => {
                    self.validate_world(snapshot)?;
                    self.start(Stage::DeletedIndex);
                    continue;
                }
                Stage::DeletedIndex => {
                    let Some(row) = snapshot.tombstones.get(self.next) else {
                        self.start(Stage::ShellWorldIndex);
                        continue;
                    };
                    self.deleted
                        .insert(row.id, crate::deletion::decode_tombstone_value(&row.value));
                }
                Stage::ShellWorldIndex => {
                    let Some(row) = snapshot.retained_claim_worlds.get(self.next) else {
                        self.start(Stage::Shells);
                        continue;
                    };
                    self.shell_worlds.insert(row.id, row.world);
                }
                Stage::Shells => {
                    let Some(row) = snapshot.retained_claim_worlds.get(self.next) else {
                        self.start(Stage::Entities);
                        continue;
                    };
                    self.validate_shell(snapshot, row)?;
                }
                Stage::Entities => {
                    let Some(entity) = snapshot.entity_blobs.get(self.next) else {
                        self.start(Stage::Edges);
                        continue;
                    };
                    self.validate_entity(snapshot, entity)?;
                }
                Stage::Edges => {
                    let Some(edge) = snapshot.base_edges.get(self.next) else {
                        self.start(Stage::Tombstones);
                        continue;
                    };
                    self.validate_edge(snapshot, edge)?;
                }
                Stage::Tombstones => {
                    let Some(tombstone) = snapshot.tombstones.get(self.next) else {
                        self.start(Stage::Complete);
                        continue;
                    };
                    Self::validate_tombstone(snapshot, tombstone)?;
                }
                Stage::Complete => return Ok(true),
            }
            self.next += 1;
            return Ok(false);
        }
    }

    fn start(&mut self, stage: Stage) {
        self.stage = stage;
        self.next = 0;
    }

    pub(in crate::recovery) fn position(&self) -> (&'static str, usize) {
        let stage = match self.stage {
            Stage::World => "world",
            Stage::DeletedIndex => "tombstone index",
            Stage::ShellWorldIndex => "shell world index",
            Stage::Shells => "retained shells",
            Stage::Entities => "entities",
            Stage::Edges => "edges",
            Stage::Tombstones => "tombstones",
            Stage::Complete => "complete",
        };
        (stage, self.next)
    }

    fn validate_world(&mut self, snapshot: &CanonicalSnapshot) -> Result<()> {
        let world = snapshot
            .window
            .split_once('@')
            .map(|(_, hex)| crate::EntityId::from_hex(hex))
            .transpose()
            .map_err(|_| invalid("window world"))?;
        if world.is_some()
            && (!snapshot.doc_snapshots.is_empty()
                || !snapshot.document_heads.is_empty()
                || !snapshot.head_move_receipts.is_empty()
                || !snapshot.note_forks.is_empty()
                || !snapshot.note_proposals.is_empty())
        {
            return Err(invalid("world window NOTE carrier"));
        }
        self.world = world;
        Ok(())
    }

    fn validate_shell(
        &self,
        snapshot: &CanonicalSnapshot,
        row: &CanonicalShellWorld,
    ) -> Result<()> {
        let world = self.world;
        let deleted = &self.deleted;
        id(row.id)?;
        let Some(world) = world else {
            return Err(invalid("base shell world proof"));
        };
        if row.world != *world.as_bytes()
            || !snapshot.entity_blobs.iter().any(|entity| {
                entity.id == row.id
                    && entity.blob.len() == ENTITY_METADATA_HEADER_LEN
                    && EntityMetadataHeader::parse(&entity.blob).is_some_and(|header| {
                        header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                            && crate::deletion::window_label_from_timestamp(header.learned_at)
                                == snapshot.window[..7]
                    })
            })
            || !deleted.get(&row.id).is_some_and(|value| {
                value.reason == Some(crate::deletion::TombstoneReason::UserDelete)
            })
        {
            return Err(invalid("retained claim world proof"));
        }
        Ok(())
    }

    fn validate_entity(
        &self,
        snapshot: &CanonicalSnapshot,
        entity: &CanonicalEntity,
    ) -> Result<()> {
        let world = self.world;
        let deleted = &self.deleted;
        let shell_worlds = &self.shell_worlds;
        id(entity.id)?;
        if let Some(tombstone) = deleted.get(&entity.id)
            && (tombstone.is_hard() || entity.blob.len() != ENTITY_METADATA_HEADER_LEN)
        {
            return Err(invalid("tombstoned entity payload"));
        }
        let header = EntityMetadataHeader::parse(&entity.blob).ok_or(invalid("entity envelope"))?;
        crate::registry::validate_entity_type(header.entity_type)?;
        if header.occurred_start > header.occurred_end {
            return Err(invalid("entity time range"));
        }
        let body = &entity.blob[ENTITY_METADATA_HEADER_LEN..];
        // A pad row rides by reference, never at rest with its pad (KS-5).
        if !crate::world_keys::image_pad_form_ok(&entity.blob) {
            return Err(invalid("world key pad at rest"));
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM && !body.is_empty() {
            let claim = crate::claim::validate_claim_body_and_decode(body, true)?;
            if claim.world != world
                || (world.is_some()
                    && crate::deletion::window_label_from_timestamp(header.learned_at)
                        != snapshot.window[..7])
            {
                return Err(invalid("claim outside window residence"));
            }
        } else if header.entity_type == crate::registry::ENTITY_TYPE_WORLD_KEY_PAD
            && world.is_some()
        {
            // A live key pad rides its world's window of the month it was
            // learned (`ITEM11_LIVE_PAD_CARRIER`).
            if crate::world_keys::pad_world_in_body(body).ok() != world
                || crate::deletion::window_label_from_timestamp(header.learned_at)
                    != snapshot.window[..7]
            {
                return Err(invalid("pad outside window residence"));
            }
        } else if header.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG
            && let Ok(entry) = crate::authority::decode_authority_log_entry_body(body)
            && let Some(side) = crate::authority::side_world(&entry.op)
        {
            // A world's side rows, its key wraps and the joins of their
            // leaves (FIX 11868), ride its window of the month they were
            // learned (`sync::types::entity_world`); its settings stay base.
            if Some(side) != world
                || crate::deletion::window_label_from_timestamp(header.learned_at)
                    != snapshot.window[..7]
            {
                return Err(invalid("key wrap outside window residence"));
            }
        } else if world.is_some()
            && (header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || !body.is_empty()
                || !deleted.contains_key(&entity.id)
                || world.as_ref().is_some_and(|world_id| {
                    shell_worlds.get(&entity.id) != Some(world_id.as_bytes())
                }))
        {
            // A bodiless CLAIM is admissible only as a soft-deletion shell,
            // bound by its tombstone and the canonical window address.
            return Err(invalid("entity outside world window"));
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE && !body.is_empty() {
            crate::note::decode_note_body_using(body, crate::note::NoteKind::wire)?;
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
            crate::authority::validate_authority_log_entry_body_bytes(body)?;
        }
        Ok(())
    }

    fn validate_edge(&self, snapshot: &CanonicalSnapshot, edge: &CanonicalBaseEdge) -> Result<()> {
        let deleted = &self.deleted;
        id(edge.source)?;
        id(edge.target)?;
        if deleted
            .get(&edge.source)
            .is_some_and(crate::deletion::DecodedTombstoneValue::is_hard)
            || deleted
                .get(&edge.target)
                .is_some_and(crate::deletion::DecodedTombstoneValue::is_hard)
        {
            return Err(invalid("hard-deleted edge endpoint"));
        }
        let kind = crate::edge::EdgeKind::try_from_u8(edge.kind).ok_or(invalid("edge kind"))?;
        crate::edge::decode_edge_value_for_kind(kind, &edge.value)?;
        if kind == crate::EdgeKind::AddressedTo
            && snapshot.tombstones.iter().any(|row| row.id == edge.source)
        {
            trusted_soft_addressing_edge(
                snapshot,
                &id(edge.source)?,
                &id(edge.target)?,
                &edge.value,
            )?;
        }
        Ok(())
    }

    fn validate_tombstone(
        snapshot: &CanonicalSnapshot,
        tombstone: &CanonicalTombstone,
    ) -> Result<()> {
        id(tombstone.id)?;
        let decoded = crate::deletion::decode_tombstone_value(&tombstone.value);
        if decoded.reason == Some(crate::deletion::TombstoneReason::ArchivedByCleanup) {
            return Err(invalid("local-only archive in window snapshot"));
        }
        if !decoded.is_hard()
            && !snapshot
                .entity_blobs
                .iter()
                .any(|row| row.id == tombstone.id)
        {
            return Err(invalid("soft tombstone missing retained shell"));
        }
        if !matches!(tombstone.value.len(), 8 | 25)
            || tombstone.deleted_at
                != crate::deletion::decode_tombstone_value(&tombstone.value).deleted_at
        {
            return Err(invalid("tombstone timestamp or encoding"));
        }
        Ok(())
    }
}
