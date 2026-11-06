//! Owned resumable manifest and order checks over one immutable canonical snapshot.

use super::{EntityMetadataHeader, invalid, strict};
use crate::error::Result;
use crate::recovery::canonical::{CanonicalSnapshot, ExpectedContainers};

#[derive(Default)]
pub(in crate::recovery) struct ManifestValidation {
    stage: Stage,
    next: usize,
    expected_containers: ExpectedContainers,
}

#[derive(Default)]
enum Stage {
    #[default]
    Header,
    EntityStrict,
    ShellStrict,
    CustodyStrict,
    TurnStrict,
    TurnParse,
    FactStrict,
    PinStrict,
    OriginStrict,
    WorldCarriers,
    EdgeStrict,
    TombStrict,
    SuppressedStrict,
    TaskOwners,
    Origins,
    ContainerStrict,
    ContainerBuild,
    ContainerFinal,
    Complete,
}

impl ManifestValidation {
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
                Stage::Header => {
                    if crate::deletion::parse_window_label(&snapshot.window).is_none() {
                        return Err(invalid("window key"));
                    }
                    if snapshot.schema_manifest.oneiron_schema_version
                        != crate::store::STORAGE_ABI_VERSION
                        || snapshot.schema_manifest.container_schema_version != 3
                        || snapshot.schema_manifest.loro_version.is_empty()
                    {
                        return Err(invalid("unsupported schema manifest"));
                    }
                    self.start(Stage::EntityStrict);
                    continue;
                }
                Stage::EntityStrict => {
                    let Some(row) = snapshot.entity_blobs.get(self.next) else {
                        self.start(Stage::ShellStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.entity_blobs[prev].id;
                        ordered(previous, row.id)?;
                    }
                }
                Stage::ShellStrict => {
                    let Some(row) = snapshot.retained_claim_worlds.get(self.next) else {
                        self.start(Stage::CustodyStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.retained_claim_worlds[prev].id;
                        ordered(previous, row.id)?;
                    }
                }
                Stage::CustodyStrict => {
                    let Some(row) = snapshot.custody_transitions.get(self.next) else {
                        self.start(Stage::TurnStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = (
                            snapshot.custody_transitions[prev].id,
                            snapshot.custody_transitions[prev].piece,
                        );
                        let current = (row.id, row.piece);
                        ordered(previous, current)?;
                    }
                }
                Stage::TurnStrict => {
                    let Some(row) = snapshot.room_turns.get(self.next) else {
                        self.start(Stage::TurnParse);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.room_turns[prev].key.as_str();
                        ordered(previous, row.key.as_str())?;
                    }
                }
                Stage::TurnParse => {
                    let Some(row) = snapshot.room_turns.get(self.next) else {
                        self.start(Stage::FactStrict);
                        continue;
                    };
                    if !crate::room_codec::carrier_parts::is_part_key(&row.key) {
                        crate::recovery::canonical::parse_id(&row.key)?;
                    }
                }
                Stage::FactStrict => {
                    let Some(row) = snapshot.room_facts.get(self.next) else {
                        self.start(Stage::PinStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.room_facts[prev].key.as_str();
                        ordered(previous, row.key.as_str())?;
                    }
                }
                Stage::PinStrict => {
                    let Some(row) = snapshot.document_pins.get(self.next) else {
                        self.start(Stage::OriginStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.document_pins[prev].key.as_str();
                        ordered(previous, row.key.as_str())?;
                    }
                }
                Stage::OriginStrict => {
                    let Some(row) = snapshot.peer_origins.get(self.next) else {
                        self.start(Stage::WorldCarriers);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.peer_origins[prev].id;
                        ordered(previous, row.id)?;
                    }
                }
                Stage::WorldCarriers => {
                    // Custody transitions ride base windows only (OF-422).
                    if snapshot.window.contains('@') && !snapshot.custody_transitions.is_empty() {
                        return Err(invalid("custody transition in a world window"));
                    }
                    // Room turn rows ride base windows only (OF-522).
                    if snapshot.window.contains('@') && !snapshot.room_turns.is_empty() {
                        return Err(invalid("room turn row in a world window"));
                    }
                    // Room side rows too (FIX 1794).
                    if snapshot.window.contains('@') && !snapshot.room_facts.is_empty() {
                        return Err(invalid("room side row in a world window"));
                    }
                    // And document quote pins (FIX 853).
                    if snapshot.window.contains('@') && !snapshot.document_pins.is_empty() {
                        return Err(invalid("document pin in a world window"));
                    }
                    self.start(Stage::EdgeStrict);
                    continue;
                }
                Stage::EdgeStrict => {
                    let Some(row) = snapshot.base_edges.get(self.next) else {
                        self.start(Stage::TombStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = (
                            snapshot.base_edges[prev].source,
                            snapshot.base_edges[prev].kind,
                            snapshot.base_edges[prev].target,
                        );
                        let current = (row.source, row.kind, row.target);
                        ordered(previous, current)?;
                    }
                }
                Stage::TombStrict => {
                    let Some(row) = snapshot.tombstones.get(self.next) else {
                        self.start(Stage::SuppressedStrict);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.tombstones[prev].id;
                        ordered(previous, row.id)?;
                    }
                }
                Stage::SuppressedStrict => {
                    let Some(row) = snapshot.suppressed_tasks.get(self.next) else {
                        self.start(Stage::TaskOwners);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.suppressed_tasks[prev];
                        ordered(previous, *row)?;
                    }
                }
                Stage::TaskOwners => {
                    let Some(task) = snapshot.suppressed_tasks.get(self.next) else {
                        self.start(Stage::Origins);
                        continue;
                    };
                    let held = snapshot
                        .entity_blobs
                        .binary_search_by_key(task, |row| row.id)
                        .ok()
                        .and_then(|at| {
                            EntityMetadataHeader::parse(&snapshot.entity_blobs[at].blob)
                        });
                    if held.is_none_or(|header| {
                        header.entity_type != crate::registry::ENTITY_TYPE_TASK
                    }) {
                        return Err(invalid("suppressed task outside the window"));
                    }
                }
                Stage::Origins => {
                    let Some(origin) = snapshot.peer_origins.get(self.next) else {
                        self.start(Stage::ContainerStrict);
                        continue;
                    };
                    // A peer origin names a row the window holds, by the digest of its whole
                    // blob (FIX 4550): never an absent row's, nor an earlier body's.
                    let held = snapshot
                        .entity_blobs
                        .binary_search_by_key(&origin.id, |row| row.id)
                        .ok()
                        .map(|at| *blake3::hash(&snapshot.entity_blobs[at].blob).as_bytes());
                    if held != Some(origin.digest) {
                        return Err(invalid("peer origin outside the window"));
                    }
                }
                Stage::ContainerStrict => {
                    let Some(row) = snapshot.container_manifests.get(self.next) else {
                        self.start(Stage::ContainerBuild);
                        continue;
                    };
                    if let Some(prev) = self.next.checked_sub(1) {
                        let previous = snapshot.container_manifests[prev].container_id.as_str();
                        ordered(previous, row.container_id.as_str())?;
                    }
                }
                Stage::ContainerBuild => {
                    if self.expected_containers.advance_row(snapshot) {
                        self.start(Stage::ContainerFinal);
                    }
                    return Ok(false);
                }
                Stage::ContainerFinal => {
                    let expected = self.expected_containers.rows();
                    if snapshot.container_manifests.len() != expected.len() {
                        return Err(invalid("container manifest coverage"));
                    }
                    let Some(row) = expected.get(self.next) else {
                        self.start(Stage::Complete);
                        continue;
                    };
                    if snapshot.container_manifests[self.next] != *row {
                        return Err(invalid("container manifest coverage"));
                    }
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
        if matches!(self.stage, Stage::ContainerBuild) {
            return self.expected_containers.position();
        }
        let stage = match self.stage {
            Stage::Header => "header",
            Stage::EntityStrict => "entity order",
            Stage::ShellStrict => "shell order",
            Stage::CustodyStrict => "custody order",
            Stage::TurnStrict => "turn order",
            Stage::TurnParse => "turn parse",
            Stage::FactStrict => "fact order",
            Stage::PinStrict => "pin order",
            Stage::OriginStrict => "origin order",
            Stage::WorldCarriers => "world carriers",
            Stage::EdgeStrict => "edge order",
            Stage::TombStrict => "tombstone order",
            Stage::SuppressedStrict => "suppressed order",
            Stage::TaskOwners => "task owners",
            Stage::Origins => "origins",
            Stage::ContainerStrict => "container order",
            Stage::ContainerBuild => "container build",
            Stage::ContainerFinal => "container final",
            Stage::Complete => "complete",
        };
        (stage, self.next)
    }
}

fn ordered<T: Ord>(previous: T, current: T) -> Result<()> {
    strict([previous, current].into_iter())
}
