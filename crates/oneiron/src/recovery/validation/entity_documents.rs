//! Generic EntityDoc validation with owned indexes over one canonical snapshot.

use super::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, entity_history::HistoryValidation, id,
    invalid, pointer, strict,
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
                    self.validate_entity(snapshot, entity)?;
                }
                Stage::Owners => {
                    let Some(row) = snapshot.entity_documents.get(self.next) else {
                        self.start(Stage::Complete);
                        continue;
                    };
                    if !snapshot
                        .entity_blobs
                        .iter()
                        .any(|entity| entity.id == row.entity_id)
                    {
                        return Err(invalid("entity document owner absent"));
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
        if !self.forks.insert(fork.fork) {
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
        if (first.proposal_len, first.proposal_settled, first.actor)
            != (fork.proposal_len, fork.proposal_settled, fork.actor)
            || first.proposal_opener_lineage != fork.proposal_opener_lineage
            || !proposal.members.insert(fork.proposal_index)
        {
            return Err(invalid("entity document proposal bundle"));
        }

        self.fork_next += 1;
        Ok(false)
    }

    fn validate_entity(
        &self,
        snapshot: &CanonicalSnapshot,
        entity: &CanonicalEntity,
    ) -> Result<()> {
        let rows = &self.rows;
        let header = EntityMetadataHeader::parse(&entity.blob).ok_or(invalid("entity envelope"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
            || entity.blob.len() == ENTITY_METADATA_HEADER_LEN
        {
            if rows.contains_key(&entity.id) {
                return Err(invalid("entity document owner cannot be NOTE or shell"));
            }
            return Ok(());
        }
        let body = &entity.blob[ENTITY_METADATA_HEADER_LEN..];
        let ref_id = pointer(body)?;
        let row = rows
            .get(&entity.id)
            .map(|&at| &snapshot.entity_documents[at]);
        match (ref_id, row) {
            (None, None) => return Ok(()),
            (Some(ref_id), Some(row)) if ref_id == id(row.document_id)?.to_hex() => {
                if let Some(actor) = row.birth_actor {
                    id(actor)?;
                }
                if row.birth_at != header.occurred_start {
                    return Err(invalid("entity document birth timestamp"));
                }
                let mut reader = std::io::Cursor::new(body);
                let value = rmpv::decode::read_value(&mut reader)
                    .map_err(|_| invalid("entity document pointer row"))?;
                let rmpv::Value::Map(fields) = value else {
                    return Err(invalid("entity document pointer row"));
                };
                let others: Vec<_> = fields
                    .iter()
                    .filter(|(key, _)| key.as_str() != Some("entity_doc_ref"))
                    .collect();
                if others
                    .iter()
                    .any(|(key, _)| key.as_str().is_some_and(crate::ports::is_metadata_field))
                {
                    return Err(invalid("editable metadata remains in the entity row"));
                }
                match &row.field {
                    None if others.is_empty() => {}
                    Some(field)
                        if crate::ports::is_text_field(field)
                            && !others
                                .iter()
                                .any(|(key, _)| key.as_str() == Some(field.as_str())) => {}
                    _ => return Err(invalid("entity document text field")),
                }
            }
            _ => return Err(invalid("entity document coverage or pointer binding")),
        }
        Ok(())
    }
}
