//! Source consistency of every retained native input, before recipient admission.
//!
//! A valid signature or a consistent causal chain is not a native write grant.
//! The candidate keeps the remaining obligations; no local publisher or storage
//! continuation accepts this review as permission.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use loro::ID;

use super::CarriedRecordDocument;
use crate::authority::{NativeSkillCarrier, NativeSkillOrigin};
use crate::entity_doc::native_skill_state::{
    NativeMapWriteView, SkillStateFactView, inspect_inventory,
};
use crate::entity_doc::{EntityDoc, TextField, invalid, storage};
use crate::error::Result;
use crate::{EntityId, Vault};

#[derive(Clone, Copy)]
pub(super) enum NativeDocumentSource {
    Incoming,
    Local,
    Joined,
}

#[derive(Clone)]
pub(super) enum NativeSourcePosition {
    Current,
    Floor(Vec<u8>),
    Mutation(ID),
}

pub(super) struct NativeSourcePlace {
    pub(super) document: NativeDocumentSource,
    pub(super) position: NativeSourcePosition,
}

/// These requirements cannot be discharged by inspecting this collection or
/// by a decoded fact's signature, row hash, token or operation id.
pub(super) enum NativeSourceRequirement {
    /// Selection and every raw write still need the actual native owner door.
    NativeDoor {
        place: NativeSourcePlace,
        fact: Option<[u8; 32]>,
    },
    RetainedPredecessor {
        place: NativeSourcePlace,
    },
    RetainedSource {
        place: NativeSourcePlace,
        fact: [u8; 32],
        frontier: Vec<u8>,
    },
    SourceRecord {
        place: NativeSourcePlace,
        fact: [u8; 32],
        fingerprint: [u8; 32],
    },
    OriginalDocument {
        place: NativeSourcePlace,
        fact: [u8; 32],
        document: [u8; 16],
        frontier: Vec<u8>,
    },
    Carrier {
        fact: [u8; 32],
        /// None is an unsigned source, not an anonymous owner or importer.
        standing: Option<NativeSkillOrigin>,
    },
}

pub(super) struct NativeSourceReview {
    requirements: Vec<NativeSourceRequirement>,
    /// Actual signed-head and removal-race results in this same writer.
    origins: BTreeMap<NativeSkillCarrier, NativeSkillOrigin>,
}

impl NativeSourceReview {
    pub(super) fn requirements(&self) -> &[NativeSourceRequirement] {
        &self.requirements
    }

    pub(super) fn origins(&self) -> &BTreeMap<NativeSkillCarrier, NativeSkillOrigin> {
        &self.origins
    }
}

/// Reads all three real snapshots. No received bytes become a local fact,
/// FinalInput, acknowledged source or persistence owner here.
pub(super) fn review_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: &CarriedRecordDocument,
    raw: &[u8],
    incoming_snapshot: &[u8],
    local: Option<(&[u8], &[u8], &[u8])>,
    (joined_head, joined): (&storage::Head, &EntityDoc),
) -> Result<NativeSourceReview> {
    let incoming = record.document(raw, incoming_snapshot)?;
    let local_document = match local {
        Some((_, head, snapshot)) => Some((
            storage::decode::<storage::Head>(head)?,
            EntityDoc::from_snapshot(snapshot)?,
        )),
        None => None,
    };
    let mut physical = vec![raw];
    if let Some((local_raw, _, _)) = local {
        physical.push(local_raw);
    }
    let mut review = Review {
        entity: record.entity()?,
        field: record.field(),
        physical: &physical,
        requirements: Vec::new(),
        carriers: BTreeSet::new(),
        unsigned: BTreeSet::new(),
    };
    review.document(
        NativeDocumentSource::Incoming,
        &record.native().document,
        &incoming,
    )?;
    if let Some((head, local)) = &local_document {
        review.document(NativeDocumentSource::Local, &head.document, local)?;
    }
    review.document(NativeDocumentSource::Joined, &joined_head.document, joined)?;
    let origins = if review.carriers.is_empty() {
        BTreeMap::new()
    } else {
        let store = &vault.store;
        let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
            store,
            store.privacy_posture,
            txn,
        )?;
        crate::authority::native_skill_origins_in_txn(store, txn, &review.carriers, &fold)?
    };
    for carrier in &review.carriers {
        let standing = origins
            .get(carrier)
            .copied()
            .ok_or_else(|| invalid("record native carrier result"))?;
        if standing != NativeSkillOrigin::Stands {
            review.requirements.push(NativeSourceRequirement::Carrier {
                fact: carrier.token,
                standing: Some(standing),
            });
        }
    }
    for fact in review.unsigned {
        review.requirements.push(NativeSourceRequirement::Carrier {
            fact,
            standing: None,
        });
    }
    Ok(NativeSourceReview {
        requirements: review.requirements,
        origins,
    })
}

struct Review<'source> {
    entity: EntityId,
    field: &'source TextField,
    physical: &'source [&'source [u8]],
    requirements: Vec<NativeSourceRequirement>,
    carriers: BTreeSet<NativeSkillCarrier>,
    unsigned: BTreeSet<[u8; 32]>,
}

impl Review<'_> {
    fn document(
        &mut self,
        source: NativeDocumentSource,
        logical_document: &str,
        document: &EntityDoc,
    ) -> Result<()> {
        let logical_document = EntityId::from_hex(logical_document)?;
        let inventory = inspect_inventory(document)?;
        if let Some(current) = inventory.current() {
            self.fact(
                source,
                NativeSourcePosition::Current,
                logical_document,
                document,
                current,
            )?;
        }
        if let Some(floor) = inventory.floor() {
            match floor.fact {
                Some(fact) => {
                    let at_floor = document.fork(floor.frontier)?;
                    self.fact(
                        source,
                        NativeSourcePosition::Floor(floor.frontier.to_vec()),
                        logical_document,
                        &at_floor,
                        fact,
                    )?;
                }
                None => self.requirements.push(NativeSourceRequirement::NativeDoor {
                    place: NativeSourcePlace {
                        document: source,
                        position: NativeSourcePosition::Floor(floor.frontier.to_vec()),
                    },
                    fact: None,
                }),
            }
        }
        for mutation in inventory.mutations() {
            // A SWITCH's carrier retains the original fact's document id.
            // Its historical frontier must not be replayed as a different
            // document just because these coordinates happen to be known.
            let same_document = match &mutation.write {
                NativeMapWriteView::Insert(fact) => {
                    fact.operation()?.document == logical_document.as_bytes()
                }
                NativeMapWriteView::Delete => true,
            };
            if same_document {
                let replay = mutation.retained_inputs(document)?;
                if replay.before().is_none() {
                    self.requirements
                        .push(NativeSourceRequirement::RetainedPredecessor {
                            place: NativeSourcePlace {
                                document: source,
                                position: NativeSourcePosition::Mutation(mutation.id),
                            },
                        });
                }
            }
            match mutation.write {
                NativeMapWriteView::Insert(fact) => self.fact(
                    source,
                    NativeSourcePosition::Mutation(mutation.id),
                    logical_document,
                    document,
                    fact,
                )?,
                NativeMapWriteView::Delete => {
                    self.requirements.push(NativeSourceRequirement::NativeDoor {
                        place: NativeSourcePlace {
                            document: source,
                            position: NativeSourcePosition::Mutation(mutation.id),
                        },
                        fact: None,
                    });
                }
            }
        }
        Ok(())
    }

    fn fact(
        &mut self,
        source: NativeDocumentSource,
        position: NativeSourcePosition,
        logical_document: EntityId,
        document: &EntityDoc,
        fact: SkillStateFactView<'_>,
    ) -> Result<()> {
        let operation = fact.operation()?;
        let token = fact.token()?;
        if operation.entity != self.entity.as_bytes()
            || document.birth().entity != self.entity.to_hex()
            || document.birth().at != operation.birth_at
        {
            return Err(invalid("record native source birth"));
        }
        match fact.verified_carrier()? {
            Some(carrier) => {
                self.carriers.insert(carrier);
            }
            None => {
                self.unsigned.insert(token);
            }
        }
        self.requirements.push(NativeSourceRequirement::NativeDoor {
            place: NativeSourcePlace {
                document: source,
                position: position.clone(),
            },
            fact: Some(token),
        });
        if operation.document != logical_document.as_bytes() {
            self.requirements
                .push(NativeSourceRequirement::OriginalDocument {
                    place: NativeSourcePlace {
                        document: source,
                        position,
                    },
                    fact: token,
                    document: *operation.document,
                    frontier: operation.source_frontier.to_vec(),
                });
            return Ok(());
        }
        let frontier = crate::entity_doc::document::decode_frontier(operation.source_frontier)?;
        let retained = document.doc.frontiers_to_vv(&frontier).filter(|version| {
            !document.doc.is_shallow()
                || version.includes_vv(&document.doc.shallow_since_vv().to_vv())
        });
        let Some(version) = retained else {
            self.requirements
                .push(NativeSourceRequirement::RetainedSource {
                    place: NativeSourcePlace {
                        document: source,
                        position: position.clone(),
                    },
                    fact: token,
                    frontier: operation.source_frontier.to_vec(),
                });
            return Ok(());
        };
        let selected = document
            .doc
            .frontiers_to_vv(&document.doc.state_frontiers())
            .ok_or_else(|| invalid("record native selection frontier"))?;
        if !selected.includes_vv(&version) {
            return Err(invalid("record native source follows its selection"));
        }
        let original = document.fork(operation.source_frontier)?;
        let inventory = inspect_inventory(&original)?;
        match inventory.current() {
            Some(previous) => {
                let prior = previous.operation()?;
                if operation.previous != Some(&previous.token()?)
                    || prior.ordinal.checked_add(1) != Some(operation.ordinal)
                    || prior.state != operation.prior
                    || prior.entity != operation.entity
                    || prior.birth_at != operation.birth_at
                {
                    return Err(invalid("record native source predecessor"));
                }
            }
            None if operation.previous.is_some() || operation.ordinal != 1 => {
                return Err(invalid("record native source predecessor"));
            }
            None => {}
        }
        // A current row is usable as historical CORE only at this exact full
        // byte hash. Missing history is an obligation, never today's fallback.
        let raw = self
            .physical
            .iter()
            .copied()
            .find(|raw| blake3::hash(raw).as_bytes() == operation.source_core);
        if let Some(raw) = raw {
            let mut body =
                rmpv::decode::read_value(&mut std::io::Cursor::new(storage::body_with_document(
                    self.field,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                    &original,
                )?))
                .map_err(|_| invalid("record native source body"))?;
            // Project only for comparison. This is not an admitted read or a
            // replacement for the original native/source/actor/secret doors.
            crate::entity_doc::native_skill_state::project_source_state(&original, &mut body)?;
            let mut encoded = Vec::new();
            rmpv::encode::write_value(&mut encoded, &body)
                .map_err(|_| invalid("record native source body"))?;
            let record = crate::skill::decode_skill_record(&encoded)?;
            if (record.lifecycle_status, record.approval_status) != operation.prior {
                return Err(invalid("record native source prior"));
            }
        } else {
            self.requirements
                .push(NativeSourceRequirement::SourceRecord {
                    place: NativeSourcePlace {
                        document: source,
                        position,
                    },
                    fact: token,
                    fingerprint: *operation.source_core,
                });
        }
        Ok(())
    }
}
