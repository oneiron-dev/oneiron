//! Core half of `blob_artifact::esign::model`: its store-layer items live in `oneiron_store::blob_artifact::esign::model` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::esign::model::*;

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::model::{EsignCommitmentTerm, EsignDocument};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum EsignEvent {
    Drafted {
        document: EsignDocument,
    },
    Sent,
    Viewed {
        recipient: String,
    },
    /// A valid capability verified an agent's access (FIX 7855 round 2):
    /// human-Viewed evidence stays human-only, while agent field saves and
    /// sign acts land on this instead of inventing Viewed. Sets access only.
    AccessVerified {
        recipient: String,
    },
    FieldSaved {
        signature: SignatureRow,
    },
    Signed {
        recipient: String,
        next: Option<String>,
        evidence: EsignSigningEvidence,
        /// Frozen item ids and versions to which this act consented.
        items: Vec<EsignItem>,
    },
    Declined {
        recipient: String,
        reason: String,
    },
    Voided {
        reason: String,
    },
    Expired {
        recipient: Option<String>,
    },
    Reminded {
        recipient: String,
        rung: u32,
    },
    /// Authored only after native verification succeeds for every sealed item.
    Sealed {
        rejected: bool,
        item_sha256: Vec<[u8; 32]>,
        /// Same item order as `item_sha256` and the sealed manifest.
        item_profiles: Vec<super::sealer::SealProfileEvidence>,
    },
    ResealRequested {
        owner: String,
        authority: String,
    },
}

impl EsignEvent {
    pub(super) fn predicate(&self) -> &'static str {
        match self {
            Self::Drafted { .. } => DRAFT_PREDICATE,
            Self::Sent => "esign.sent",
            Self::Viewed { .. } => "esign.viewed",
            Self::AccessVerified { .. } => "esign.access_verified",
            Self::FieldSaved { .. } => "esign.field",
            Self::Signed { .. } => "esign.signed",
            Self::Declined { .. } => "esign.declined",
            Self::Voided { .. } => "esign.voided",
            Self::Expired { .. } => "esign.expired",
            Self::Reminded { .. } => "esign.reminded",
            Self::Sealed {
                rejected: false, ..
            } => "esign.completed",
            Self::Sealed { rejected: true, .. } => "esign.rejected",
            Self::ResealRequested { .. } => "esign.reseal_requested",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignEventRow {
    pub sequence: u64,
    pub previous_sha256: [u8; 32],
    pub event: EsignEvent,
    pub actor: EsignAuditActor,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EsignState {
    pub document: EsignDocument,
    pub status: DocumentStatus,
    pub recipients: BTreeMap<String, RecipientState>,
    /// One current signature/value per field, never a duplicate signature row.
    pub signatures: BTreeMap<String, SignatureRow>,
    pub rejection: Option<String>,
    pub sealed_sha256: Vec<[u8; 32]>,
    pub reseal_pending: bool,
    pub reminders: BTreeSet<(String, u32)>,
    pub(super) sent_at: Option<u64>,
    pub(super) reminder_at: BTreeMap<String, u64>,
}

/// A draft refuses only what it cannot be: no count or size cap on its items,
/// recipients, fields, titles, names or choices (Rule 5). The one length bound
/// left is the mail format's ([`EMAIL_MAX_BYTES`]).
pub(super) fn validate_document(doc: &EsignDocument, now: u64) -> Result<()> {
    if doc.schema_version != 1
        || doc.title.is_empty()
        || doc.items.is_empty()
        || doc.expires_at <= now
    {
        return Err(invalid("invalid document bounds"));
    }
    if let Some(rules) = &doc.lifecycle {
        rules.validate()?;
    }
    let mut items = BTreeSet::new();
    for item in &doc.items {
        reference(&item.artifact_ref)?;
        if item.original_version == 0 || !items.insert(&item.artifact_ref) {
            return Err(invalid("invalid item"));
        }
    }
    let mut recipients = BTreeSet::new();
    for r in &doc.recipients {
        reference(&r.id)?;
        if let Some(principal) = &r.principal_ref {
            reference(principal)?;
        }
        if !recipients.insert(&r.id)
            || r.email.len() > EMAIL_MAX_BYTES
            || !r.email.contains('@')
            || r.email.contains(['\r', '\n'])
            || r.expires_at <= now
            || r.expires_at > doc.expires_at
        {
            return Err(invalid("invalid recipient"));
        }
        if let Some(basis) = &r.natural_person
            && (basis.trim().is_empty()
                || !matches!(r.role, RecipientRole::Signer | RecipientRole::Approver))
        {
            return Err(invalid("invalid natural-person requirement"));
        }
        if r.natural_person.is_some() && r.automated {
            return Err(invalid(
                "the law keeps this signature with a natural person",
            ));
        }
    }
    for term in &doc.commitments {
        reference(&term.obligor.entity_ref)?;
        reference(&term.beneficiary)?;
    }
    let mut fields = BTreeSet::new();
    for f in &doc.fields {
        reference(&f.id)?;
        let g = &f.geometry;
        if !fields.insert(&f.id)
            || !recipients.contains(&f.recipient)
            || !doc.recipients.iter().any(|r| {
                r.id == f.recipient
                    && matches!(r.role, RecipientRole::Signer | RecipientRole::Approver)
            })
            || f.item as usize >= doc.items.len()
            || g.page == 0
            || [g.x_percent, g.y_percent, g.width_percent, g.height_percent]
                .iter()
                .any(|v| !v.is_finite() || *v < 0.0 || *v > 100.0)
            || g.width_percent == 0.0
            || g.height_percent == 0.0
            || g.x_percent + g.width_percent > 100.0
            || g.y_percent + g.height_percent > 100.0
        {
            return Err(invalid("invalid field geometry or owner"));
        }
        match &f.meta {
            // The author's declared max_bytes is the form's contract; the
            // engine adds no outer cap on it (Rule 5).
            FieldMeta::Text { max_bytes } if *max_bytes == 0 => {
                return Err(invalid("invalid text field"));
            }
            // The choices never reach the PDF (only the chosen value is
            // burned in), so no form-field bound applies to them.
            FieldMeta::Select { options }
                if options.is_empty()
                    || options.iter().any(String::is_empty)
                    || options.iter().collect::<BTreeSet<_>>().len() != options.len() =>
            {
                return Err(invalid("invalid choices"));
            }
            _ => {}
        }
    }
    Ok(())
}
