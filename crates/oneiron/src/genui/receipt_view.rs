//! Receipt view component, deep-link kinds and commitment link resolver.

use super::consent_eval::{atom_id, lens_text, meta_line, non_empty};
use crate::claim::ClaimLifecycleStatus;
use crate::commitment::decode_commitment_claim;
use crate::entity_id::EntityId;
use crate::lens::{LensAtom, LensNode, ReceiptAtom, SealAtom, SealLevel};
use crate::receipt::{COMMITMENT_TRIGGER_PREFIX, ReceiptRecord, commitment_trigger_ref};
use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptViewComponent {
    pub component_id: String,
    pub receipt: ReceiptRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ReceiptDeepLink>,
}

impl ReceiptViewComponent {
    pub fn new(
        component_id: impl Into<String>,
        receipt: ReceiptRecord,
        links: Vec<ReceiptDeepLink>,
    ) -> Result<Self> {
        let component_id = non_empty("receipt_view component_id", component_id.into())?;
        Ok(Self {
            component_id,
            receipt,
            links,
        })
    }

    #[must_use]
    pub fn title(&self) -> String {
        format!("{} receipt", self.receipt.receipt_kind.as_str())
    }

    #[must_use]
    pub fn receipt_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("outcome: {}", self.receipt.outcome),
            format!("occurred_at: {}", self.receipt.occurred_at),
        ];
        if let Some(actor) = self.receipt.actor.as_deref() {
            lines.push(format!("actor: {actor}"));
        }
        if let Some(on_behalf_of) = self.receipt.on_behalf_of.as_deref() {
            lines.push(format!("on_behalf_of: {on_behalf_of}"));
        }
        if let Some(trigger_ref) = self.receipt.trigger_ref.as_deref() {
            lines.push(format!("trigger_ref: {trigger_ref}"));
        }
        lines.extend(
            self.links
                .iter()
                .map(|link| format!("link: {}", link.fallback_text())),
        );
        lines
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        self.receipt_lines().join(" | ")
    }

    pub(super) fn atom_kit_root(&self) -> Result<LensNode> {
        let mut lines = vec![
            meta_line("kind", self.receipt.receipt_kind.as_str())?,
            meta_line("outcome", &self.receipt.outcome)?,
            meta_line("occurred_at", &self.receipt.occurred_at.to_string())?,
        ];
        if let Some(trigger_ref) = self.receipt.trigger_ref.as_deref() {
            lines.push(meta_line("trigger_ref", trigger_ref)?);
        }
        for link in &self.links {
            lines.push(meta_line(&link.label, &link.fallback_text())?);
        }

        Ok(LensNode::new(
            atom_id("receipt-view-root")?,
            LensAtom::Receipt(ReceiptAtom {
                title: lens_text(self.title())?,
                lines,
                seal: Some(SealAtom {
                    level: SealLevel::Actor,
                    label: lens_text("receipt_view")?,
                }),
            }),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDeepLink {
    pub target_kind: ReceiptDeepLinkKind,
    pub target_ref: String,
    pub label: String,
    pub resolution: ViewTimeResolution,
}

impl ReceiptDeepLink {
    pub fn new(
        target_kind: ReceiptDeepLinkKind,
        target_ref: impl Into<String>,
        label: impl Into<String>,
        resolution: ViewTimeResolution,
    ) -> Result<Self> {
        Ok(Self {
            target_kind,
            target_ref: non_empty("receipt deep-link target_ref", target_ref.into())?,
            label: non_empty("receipt deep-link label", label.into())?,
            resolution,
        })
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        format!(
            "{} -> {} ({})",
            self.label,
            self.target_ref,
            self.resolution.as_str()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDeepLinkKind {
    Commitment,
    TranscriptMoment,
    Brief,
    Share,
    AccessGrant,
    Entity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTimeResolution {
    Active,
    Revoked,
    Unavailable,
}

impl ViewTimeResolution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Resolves a commitment-sourced receipt into a view-time deep link.
///
/// `Ok(None)` means the receipt does not name a commitment at all — a
/// non-commitment `intent_source`, or a commitment-sourced receipt whose
/// trigger is absent or carries some other prefix. Once a receipt DOES name a
/// commitment, this either produces a link or fails typed; it never degrades a
/// real reference into silence.
///
/// Resolution is about READABILITY at view time, not about whether the
/// obligation is still open. A fulfilled, released, lapsed or superseded
/// commitment resolves [`ViewTimeResolution::Active`] because its history is
/// still there to be read — that is the whole point of a receipt deep link.
/// Only a RETRACTED claim head resolves [`ViewTimeResolution::Revoked`]:
/// retraction is the owner saying the belief should not have been recorded,
/// and the link must say so rather than quietly showing it.
///
/// # Errors
///
/// [`Error::InvalidKey`] for a malformed `commitment:` suffix,
/// [`Error::EntityNotFound`] when no claim head exists under the referenced
/// id, [`Error::InvalidClaimBody`] when that head is not a `commitment.record`
/// claim, and the [`ReceiptDeepLink::new`] validation errors for an empty
/// label.
pub fn resolve_commitment_receipt_link(
    vault: &Vault,
    receipt: &ReceiptRecord,
    label: impl Into<String>,
) -> Result<Option<ReceiptDeepLink>> {
    let Some(target_ref) = commitment_trigger_ref(receipt)? else {
        return Ok(None);
    };
    let id = EntityId::from_hex(
        target_ref
            .strip_prefix(COMMITMENT_TRIGGER_PREFIX)
            .unwrap_or(target_ref.as_str()),
    )?;

    // The ungated targeted read on purpose: this is the history door, and a
    // closed commitment must stay reachable from the receipt that cited it.
    let body = vault.get_claim(&id)?.ok_or(Error::EntityNotFound)?;
    decode_commitment_claim(&body)?.ok_or(Error::InvalidClaimBody(
        "claim predicate is not commitment.record",
    ))?;

    let resolution = match body.lifecycle {
        ClaimLifecycleStatus::Retracted => ViewTimeResolution::Revoked,
        ClaimLifecycleStatus::Active | ClaimLifecycleStatus::Superseded => {
            ViewTimeResolution::Active
        }
    };
    ReceiptDeepLink::new(
        ReceiptDeepLinkKind::Commitment,
        target_ref,
        label,
        resolution,
    )
    .map(Some)
}
