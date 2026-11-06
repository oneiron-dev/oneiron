//! Actual original native door checks, separate from recipient write permission.
//!
//! Only a retained operation whose causal input is its exact advertised source
//! reaches these checks. Reselections, deletes and purged sources keep their own
//! obligations. Actor, content, secret, hub and ordinary put gates remain required.

use heed::RoTxn;

use super::native_sources::NativeSourcePlace;
use crate::entity_doc::native_skill_state::{SkillStateDoorView, SkillStateFactView};
use crate::entity_doc::{EntityDoc, invalid, storage};
use crate::error::Result;
use crate::skill::SkillSupersessionRead;
use crate::{EntityId, Vault};

/// A checked native Update or Supersede law at one actual retained occurrence.
/// This is not a local publication, accepted native operation or storage owner.
pub(super) struct NativeDoorCheck {
    place: NativeSourcePlace,
    fact: [u8; 32],
    successor: Option<SkillSupersessionRead>,
}

impl NativeDoorCheck {
    pub(super) fn place(&self) -> &NativeSourcePlace {
        &self.place
    }

    pub(super) fn fact(&self) -> &[u8; 32] {
        &self.fact
    }

    pub(super) fn recheck_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
        match &self.successor {
            Some(source) => source.replay_source_matches_in_txn(&vault.store, txn),
            None => Ok(true),
        }
    }
}

pub(super) enum NativeDoorReview {
    Checked(NativeDoorCheck),
    /// A source-changing rewrite needs its genuine canonical/reselection owner.
    OtherContinuation,
    /// The exact successor is not this writer's current read source.
    SuccessorUnavailable,
}

/// Check the native door only after source consistency has bound the full raw
/// source and its original logical document. No current-row or floor fallback.
pub(super) fn check_original_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    place: NativeSourcePlace,
    fact: SkillStateFactView<'_>,
    raw: &[u8],
    field: &crate::entity_doc::TextField,
    source: &EntityDoc,
    before: &EntityDoc,
    old_id: &EntityId,
) -> Result<NativeDoorReview> {
    let source_version = source
        .doc
        .frontiers_to_vv(&source.doc.state_frontiers())
        .ok_or_else(|| invalid("native door source version"))?;
    let before_version = before
        .doc
        .frontiers_to_vv(&before.doc.state_frontiers())
        .ok_or_else(|| invalid("native door predecessor version"))?;
    if before_version != source_version {
        return Ok(NativeDoorReview::OtherContinuation);
    }
    let operation = fact.operation()?;
    if blake3::hash(raw).as_bytes() != operation.source_core {
        return Err(invalid("native door source record"));
    }
    let body = storage::body_with_document(
        field,
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        source,
    )?;
    let prior = crate::skill::decode_skill_record(&body)?;
    if (prior.lifecycle_status, prior.approval_status) != operation.prior {
        return Err(invalid("native door prior state"));
    }
    // The native operation changes exactly its two state axes. No arbitrary
    // received final body, unknown-field rewrite or logical rehash enters here.
    let mut updated = prior.clone();
    (updated.lifecycle_status, updated.approval_status) = operation.state;
    let successor = match operation.door {
        SkillStateDoorView::Update => {
            crate::skill::validate_skill_update_door(&prior, &updated)?;
            None
        }
        SkillStateDoorView::Supersede {
            successor,
            source_core,
            logical_body,
            document_pin,
        } => {
            crate::skill::validate_skill_update(&prior, &updated)?;
            let Some(source) = SkillSupersessionRead::capture_replay_in_txn(
                &vault.store,
                txn,
                EntityId::from_bytes(*successor)?,
                source_core,
                logical_body,
                document_pin,
            )?
            else {
                return Ok(NativeDoorReview::SuccessorUnavailable);
            };
            source.validate_replay_in_txn(&vault.store, txn, old_id, &prior)?;
            Some(source)
        }
    };
    Ok(NativeDoorReview::Checked(NativeDoorCheck {
        place,
        fact: fact.token()?,
        successor,
    }))
}
