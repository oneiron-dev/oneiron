//! OF-491: what `vault.shares.revoke` and `vault.shares.view` answer.
//!
//! A revoke answers the share it stopped and when. A view answers the
//! shared brief as its recipient may see it now, or nothing: a share that
//! does not resolve for the viewer and one that does not exist answer the
//! same `None`, under the read's receipt. The view is ephemeral; a host
//! renders it and keeps nothing.

use serde::{Deserialize, Serialize};

use crate::share_travel::BornWith;

/// `vault.shares.revoke`'s answer: the share, its status after the revoke,
/// and the instant it stopped. A share already revoked answers its first
/// revocation unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRevokeReceipt {
    /// The share's id, as 32 hex.
    pub share_ref: String,
    /// The grant's stored status: `revoked`.
    pub status: String,
    /// When the share stopped, Unix seconds on the vault's clock.
    pub revoked_at: Option<u64>,
}

/// One pinned citation of a shared brief, as the viewer may see it. A
/// citation the share or the viewer's own read withholds is `redacted`, and
/// then says nothing of its lifecycle, confidence or quote.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedBriefCitation {
    /// The cited CLAIM, as 32 hex.
    pub claim_ref: String,
    pub stale: bool,
    pub drifted: bool,
    pub redacted: bool,
    pub confidence: Option<f32>,
    /// `active`, `superseded` or `retracted`; none when redacted.
    pub lifecycle: Option<String>,
    pub quote: Option<String>,
}

/// `vault.shares.view`'s value: the shared brief rendered fresh for its
/// recipient. The read receipt beside it folds every read the render made,
/// the instrument's interpolations included.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedBriefView {
    /// The share opened, as 32 hex.
    pub share_ref: String,
    /// The escaped Instrument HTML of the brief's text.
    pub html: String,
    pub citations: Vec<SharedBriefCitation>,
    /// The born-with text the sharer let travel with this share.
    pub born_with: BornWith,
}

#[cfg(feature = "sync")]
impl SharedBriefView {
    /// The wire form of one rendered shared brief.
    #[must_use]
    pub fn project(share_id: &crate::EntityId, view: crate::note::BriefView) -> Self {
        Self {
            share_ref: share_id.to_hex(),
            html: view.instrument.html,
            citations: view
                .citations
                .into_iter()
                .map(|citation| SharedBriefCitation {
                    claim_ref: citation.claim.to_hex(),
                    stale: citation.stale,
                    drifted: citation.drifted,
                    redacted: citation.redacted,
                    confidence: citation.confidence,
                    lifecycle: citation
                        .lifecycle
                        .map(|lifecycle| lifecycle.as_str().to_owned()),
                    quote: citation.quote,
                })
                .collect(),
            born_with: view.born_with,
        }
    }
}
