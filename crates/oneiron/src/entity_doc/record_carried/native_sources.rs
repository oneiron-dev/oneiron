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

#[derive(Clone)]
pub(super) struct NativeSourcePlace {
    pub(super) document: NativeDocumentSource,
    pub(super) position: NativeSourcePosition,
}

/// Source-accounting items for the actual recipient or authorized continuation.
/// They are not a policy requiring historical actor/shared-grant replay, and
/// an unknown item alone is not a new refusal. Inspecting this collection or a
/// decoded signature, row hash, token or operation id grants no permission.
pub(super) enum NativeSourceRequirement {
    /// Bind selection and every raw write to the actual whole continuation.
    /// A separately checked original door law is not that recipient owner.
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
    native_doors: Vec<super::native_doors::NativeDoorCheck>,
}

impl NativeSourceReview {
    pub(super) fn requirements(&self) -> &[NativeSourceRequirement] {
        &self.requirements
    }

    pub(super) fn origins(&self) -> &BTreeMap<NativeSkillCarrier, NativeSkillOrigin> {
        &self.origins
    }

    pub(super) fn native_doors(&self) -> &[super::native_doors::NativeDoorCheck] {
        &self.native_doors
    }

    /// A later operation in the same writer may have changed signed-head
    /// availability or the removal race without touching document storage.
    pub(super) fn recheck_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
        let carriers = self.origins.keys().cloned().collect();
        if origins_in_txn(vault, txn, &carriers)? != self.origins {
            return Ok(false);
        }
        for checked in &self.native_doors {
            if !checked.recheck_in_txn(vault, txn)? {
                return Ok(false);
            }
        }
        Ok(true)
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
    first: Option<&super::RefinementOriginSource>,
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
    // The transported FIRST is another exact historical CORE candidate,
    // never the current receiver row or a local revision reference. A fact
    // can use it only at its original full raw source_core hash below.
    if let Some(first) = first {
        physical.push(first.raw());
    }
    let mut review = Review {
        vault,
        txn,
        entity: record.entity()?,
        field: record.field(),
        physical: &physical,
        requirements: Vec::new(),
        carriers: BTreeSet::new(),
        unsigned: BTreeSet::new(),
        native_doors: Vec::new(),
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
    let origins = origins_in_txn(vault, txn, &review.carriers)?;
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
        native_doors: review.native_doors,
    })
}

fn origins_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    carriers: &BTreeSet<NativeSkillCarrier>,
) -> Result<BTreeMap<NativeSkillCarrier, NativeSkillOrigin>> {
    if carriers.is_empty() {
        return Ok(BTreeMap::new());
    }
    let store = &vault.store;
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    crate::authority::native_skill_origins_in_txn(store, txn, carriers, &fold)
}

struct Review<'source, 'txn, 'env> {
    vault: &'source Vault,
    txn: &'txn RoTxn<'env>,
    entity: EntityId,
    field: &'source TextField,
    physical: &'source [&'source [u8]],
    requirements: Vec<NativeSourceRequirement>,
    carriers: BTreeSet<NativeSkillCarrier>,
    unsigned: BTreeSet<[u8; 32]>,
    native_doors: Vec<super::native_doors::NativeDoorCheck>,
}

impl Review<'_, '_, '_> {
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
                None,
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
                        None,
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
            let replay = if same_document {
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
                Some(replay)
            } else {
                None
            };
            match mutation.write {
                NativeMapWriteView::Insert(fact) => self.fact(
                    source,
                    NativeSourcePosition::Mutation(mutation.id),
                    logical_document,
                    document,
                    fact,
                    replay.as_ref().and_then(|replay| replay.before()),
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
        before: Option<&EntityDoc>,
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
            // The supplied-source reader projects only this exact version,
            // including its genuine selected None. It grants no admission.
            let body = storage::body_with_document(
                self.field,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                &original,
            )?;
            let record = crate::skill::decode_skill_record(&body)?;
            if (record.lifecycle_status, record.approval_status) != operation.prior {
                return Err(invalid("record native source prior"));
            }
            if let Some(before) = before {
                match super::native_doors::check_original_in_txn(
                    self.vault,
                    self.txn,
                    NativeSourcePlace {
                        document: source,
                        position: position.clone(),
                    },
                    fact,
                    raw,
                    self.field,
                    &original,
                    before,
                    &EntityId::from_bytes(*operation.entity)?,
                )? {
                    super::native_doors::NativeDoorReview::Checked(checked) => {
                        self.native_doors.push(checked);
                    }
                    // These need their actual continuation or retained successor.
                    // The original NativeDoor obligation remains in every case.
                    super::native_doors::NativeDoorReview::OtherContinuation
                    | super::native_doors::NativeDoorReview::SuccessorUnavailable => {}
                }
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
