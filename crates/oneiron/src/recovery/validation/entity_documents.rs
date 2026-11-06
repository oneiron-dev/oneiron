//! Generic EntityDoc validation with owned indexes over one canonical snapshot.

use super::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, entity_history::HistoryValidation,
    entity_pointer::EntityPointer, id, invalid, strict,
};
use crate::error::Result;
use crate::recovery::canonical::{
    CanonicalDocumentFork, CanonicalEntity, CanonicalEntityDocument, CanonicalSnapshot,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Default)]
pub(in crate::recovery) struct EntityDocumentRows {
    stage: Stage,
    next: usize,
    history: HistoryValidation,
    history_complete: bool,
    fork_next: usize,
    lineage_next: Option<usize>,
    owner_next: usize,
    entity_pointer: EntityPointer,
    previous: Option<[u8; 16]>,
    last_proposal: Option<[u8; 16]>,
    proposals: BTreeMap<[u8; 16], Proposal>,
    forks: BTreeSet<[u8; 16]>,
    rows: BTreeMap<[u8; 16], usize>,
}

struct Proposal {
    first_row: usize,
    first_fork: usize,
    members: BTreeSet<u64>,
}

impl Proposal {
    fn first<'snapshot>(
        &self,
        snapshot: &'snapshot CanonicalSnapshot,
    ) -> &'snapshot CanonicalDocumentFork {
        &snapshot.entity_documents[self.first_row]
            .history
            .as_ref()
            .expect("proposal cursor was captured from this immutable history")
            .forks[self.first_fork]
    }
}

#[derive(Default)]
enum Stage {
    #[default]
    Order,
    Histories,
    Proposals,
    Index,
    Entities,
    Owners,
    Complete,
}

impl EntityDocumentRows {
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
                Stage::Order => {
                    let Some(row) = snapshot.entity_documents.get(self.next) else {
                        self.start(Stage::Histories);
                        continue;
                    };
                    strict(
                        self.previous
                            .into_iter()
                            .chain(std::iter::once(row.entity_id)),
                    )?;
                    self.previous = Some(row.entity_id);
                }
                Stage::Histories => {
                    let Some(row) = snapshot.entity_documents.get(self.next) else {
                        self.start(Stage::Proposals);
                        continue;
                    };
                    if !self.validate_row_history(snapshot, row)? {
                        return Ok(false);
                    }
                }
                Stage::Proposals => {
                    let entry = match self.last_proposal {
                        Some(last) => self.proposals.range((Excluded(last), Unbounded)).next(),
                        None => self.proposals.first_key_value(),
                    };
                    let Some((key, proposal)) = entry else {
                        self.proposals.clear();
                        self.forks.clear();
                        self.start(Stage::Index);
                        continue;
                    };
                    if usize::try_from(proposal.first(snapshot).proposal_len).ok()
                        != Some(proposal.members.len())
                    {
                        return Err(invalid(
                            "entity document proposal spans entities outside the snapshot",
                        ));
                    }
                    self.last_proposal = Some(*key);
                }
                Stage::Index => {
                    let Some(row) = snapshot.entity_documents.get(self.next) else {
                        self.start(Stage::Entities);
                        continue;
                    };
                    self.rows.insert(row.entity_id, self.next);
                }
                Stage::Entities => {
                    let Some(entity) = snapshot.entity_blobs.get(self.next) else {
                        self.start(Stage::Owners);
                        continue;
                    };
                    if !self.validate_entity(snapshot, entity)? {
                        return Ok(false);
                    }
                }
                Stage::Owners => {
                    let Some(row) = snapshot.entity_documents.get(self.next) else {
                        self.start(Stage::Complete);
                        continue;
                    };
                    let Some(entity) = snapshot.entity_blobs.get(self.owner_next) else {
                        return Err(invalid("entity document owner absent"));
                    };
                    self.owner_next += 1;
                    if entity.id != row.entity_id {
                        return Ok(false);
                    }
                    self.owner_next = 0;
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
            Stage::Order => "order",
            Stage::Histories => "histories",
            Stage::Proposals => "proposal completeness",
            Stage::Index => "owner index",
            Stage::Entities => "entity coverage",
            Stage::Owners => "owners",
            Stage::Complete => "complete",
        };
        (stage, self.next)
    }

    fn validate_row_history(
        &mut self,
        snapshot: &CanonicalSnapshot,
        row: &CanonicalEntityDocument,
    ) -> Result<bool> {
        if !self.history_complete {
            if !self.history.advance_row(row)? {
                return Ok(false);
            }
            crate::entity_doc::validate_canonical_skill_state(row)?;
            self.history_complete = true;
            return Ok(false);
        }
        let Some(fork) = row
            .history
            .as_ref()
            .and_then(|history| history.forks.get(self.fork_next))
        else {
            self.history = HistoryValidation::default();
            self.history_complete = false;
            self.fork_next = 0;
            return Ok(true);
        };
        let first_row = self.next;
        let fork_index = self.fork_next;
        let starting = self.lineage_next.is_none();
        if starting && !self.forks.insert(fork.fork) {
            return Err(invalid("entity document fork duplicated"));
        }
        let proposal = self
            .proposals
            .entry(fork.proposal)
            .or_insert_with(|| Proposal {
                first_row,
                first_fork: fork_index,
                members: BTreeSet::new(),
            });
        let first = proposal.first(snapshot);
        if starting
            && ((first.proposal_len, first.proposal_settled, first.actor)
                != (fork.proposal_len, fork.proposal_settled, fork.actor)
                || first.proposal_opener_lineage.len() != fork.proposal_opener_lineage.len())
        {
            return Err(invalid("entity document proposal bundle"));
        }
        let next = self.lineage_next.get_or_insert(0);
        if let Some(lineage) = first.proposal_opener_lineage.get(*next) {
            if lineage != &fork.proposal_opener_lineage[*next] {
                return Err(invalid("entity document proposal bundle"));
            }
            *next += 1;
            return Ok(false);
        }
        if !proposal.members.insert(fork.proposal_index) {
            return Err(invalid("entity document proposal bundle"));
        }

        self.lineage_next = None;
        self.fork_next += 1;
        Ok(false)
    }

    fn validate_entity(
        &mut self,
        snapshot: &CanonicalSnapshot,
        entity: &CanonicalEntity,
    ) -> Result<bool> {
        let rows = &self.rows;
        let header = EntityMetadataHeader::parse(&entity.blob).ok_or(invalid("entity envelope"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
            || entity.blob.len() == ENTITY_METADATA_HEADER_LEN
        {
            if rows.contains_key(&entity.id) {
                return Err(invalid("entity document owner cannot be NOTE or shell"));
            }
            return Ok(true);
        }
        let body = &entity.blob[ENTITY_METADATA_HEADER_LEN..];
        let row = rows
            .get(&entity.id)
            .map(|&at| &snapshot.entity_documents[at]);
        if !self
            .entity_pointer
            .advance(body, row.and_then(|row| row.field.as_deref()))
        {
            return Ok(false);
        }
        let ref_id = self.entity_pointer.pointer(body)?;
        match (ref_id, row) {
            (None, None) => {}
            (Some(ref_id), Some(row)) if ref_id == id(row.document_id)?.to_hex() => {
                if let Some(actor) = row.birth_actor {
                    id(actor)?;
                }
                if row.birth_at != header.occurred_start {
                    return Err(invalid("entity document birth timestamp"));
                }
                if self.entity_pointer.metadata {
                    return Err(invalid("editable metadata remains in the entity row"));
                }
                match &row.field {
                    None if !self.entity_pointer.other_fields => {}
                    Some(field)
                        if crate::ports::is_text_field(field)
                            && !self.entity_pointer.body_field => {}
                    _ => return Err(invalid("entity document text field")),
                }
            }
            _ => return Err(invalid("entity document coverage or pointer binding")),
        }
        self.entity_pointer = EntityPointer::default();
        Ok(true)
    }
}
