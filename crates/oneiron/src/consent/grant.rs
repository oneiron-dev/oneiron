use crate::entity_id::EntityId;
use crate::store::{GateDecisionId, GateDecisionRecord};

#[doc(hidden)]
pub use oneiron_consent_state::consent::grant::{
    ActionGrant, CONSENT_REASON_APPROVE_ONCE, CONSENT_REASON_BYPASS_CREATED,
    CONSENT_REASON_BYPASSED, CONSENT_REASON_CODE_WAIT_CONSUMED, CONSENT_REASON_CODE_WAIT_SETTLED,
    CONSENT_REASON_DENIED, CONSENT_REASON_REVOKED, CONSENT_REASON_STANDING_CREATED,
    CONSENT_REASON_STANDING_USED, CodeWaitReceiptLinks, ConsentGrant, ConsentGrantRow,
    ConsentGrantStatus, ConsentGuard, ConsentOwnerStamp, ConsentProposal, ConsentReceipt,
    DisclosureGrant, StandingConsentGrant,
};
#[doc(hidden)]
use oneiron_consent_state::consent::grant::{CODE_WAIT_CONSUMED_KIND, CODE_WAIT_SETTLED_KIND};

/// The stable registry reference for this row: the bound digest hex, or
/// for a bypass grant the digest of its bound, scope and floor version.
#[must_use]
pub fn consent_grant_row_grant_ref(consent_grant_row: &ConsentGrantRow) -> String {
    match &consent_grant_row.bypass {
        None => consent_grant_row.grant.bound().digest().to_hex(),
        Some(extent) => crate::consent::bypass::bypass_extent_grant_ref(
            &extent,
            consent_grant_row.grant.bound(),
        ),
    }
}

/// The code wait receipt a consent Gate record holds, read back from its
/// `diff_handle`: the typed inverse of the encoder above, for these two
/// variants only (FIX 4608). `None` for any other record: another
/// content kind or receipt, a kind byte its outcome and reason code do
/// not name, or bytes this encoder would not write exactly.
pub(crate) fn code_wait_receipt_links_from_gate_record(
    record: &GateDecisionRecord,
) -> Option<ConsentReceipt> {
    let (&kind, rest) = record.diff_handle.split_first()?;
    let (&flags, rest) = rest.split_first()?;
    let slot = |at: usize| -> Option<[u8; 16]> { rest.get(at..at + 16)?.try_into().ok() };
    let links = CodeWaitReceiptLinks {
        wait_id: EntityId::from_bytes(slot(0)?).ok()?,
        word_ref: if flags & 1 == 0 {
            None
        } else {
            Some(EntityId::from_bytes(slot(16)?).ok()?)
        },
        prior_receipt: if flags & 2 == 0 {
            None
        } else {
            Some(GateDecisionId::from_bytes(slot(32)?))
        },
        facts_digest: rest.get(48..80)?.try_into().ok()?,
    };
    let receipt = if kind == CODE_WAIT_CONSUMED_KIND {
        ConsentReceipt::CodeWaitConsumed {
            decision_id: record.decision_id,
            links,
        }
    } else {
        ConsentReceipt::CodeWaitSettled {
            decision_id: record.decision_id,
            links,
            outcome: crate::consent::code_wait_state::CodeConsentSettleOutcome::from_tag(
                kind & 0x0f,
            )?,
        }
    };
    (record.content_kind == CONSENT_CONTENT_KIND
        && record.outcome == receipt.gate_outcome()
        && record.reason_codes.first().map(String::as_str) == Some(receipt.reason_code())
        && crate::consent::consent_receipt_diff_handle(&receipt) == record.diff_handle)
        .then_some(receipt)
}

/// The standing-grant row this receipt joins, when it has one.
#[must_use]
pub fn consent_receipt_grant_ref(consent_receipt: &ConsentReceipt) -> Option<String> {
    match consent_receipt {
        ConsentReceipt::Approved {
            grant: ConsentGrant::Standing(grant),
            ..
        } => Some(grant.bound().digest().to_hex()),
        ConsentReceipt::Used { grant_ref, .. }
        | ConsentReceipt::Revoked { grant_ref, .. }
        | ConsentReceipt::BypassCreated { grant_ref, .. }
        | ConsentReceipt::Bypassed { grant_ref, .. } => Some(grant_ref.clone()),
        ConsentReceipt::Approved {
            grant: ConsentGrant::ApproveOnce(_),
            ..
        }
        | ConsentReceipt::Denied { .. }
        | ConsentReceipt::CodeWaitSettled { .. }
        | ConsentReceipt::CodeWaitConsumed { .. } => None,
    }
}

/// The effect/bound digest this receipt projects into `diff_handle`.
#[must_use]
pub fn consent_receipt_diff_handle(consent_receipt: &ConsentReceipt) -> Vec<u8> {
    match consent_receipt {
        ConsentReceipt::Approved {
            grant: ConsentGrant::ApproveOnce(digest),
            ..
        }
        | ConsentReceipt::Used {
            effect_digest: digest,
            ..
        }
        | ConsentReceipt::Denied {
            effect_digest: digest,
            ..
        }
        | ConsentReceipt::BypassCreated {
            bound_digest: digest,
            ..
        }
        | ConsentReceipt::Bypassed {
            effect_digest: digest,
            ..
        } => digest.as_bytes().to_vec(),
        ConsentReceipt::Approved {
            grant: ConsentGrant::Standing(grant),
            ..
        } => grant.bound().digest().as_bytes().to_vec(),
        // A revoke names the row, not an op: the row ref IS the bound
        // digest, so the handle stays a digest rather than free text.
        ConsentReceipt::Revoked { grant_ref, .. } => grant_ref.as_bytes().to_vec(),
        ConsentReceipt::CodeWaitSettled { links, outcome, .. } => {
            links.diff_handle(CODE_WAIT_SETTLED_KIND | outcome.tag())
        }
        ConsentReceipt::CodeWaitConsumed { links, .. } => {
            links.diff_handle(CODE_WAIT_CONSUMED_KIND)
        }
    }
}

/// The pinned Gate `content_kind` for consent-registry decisions.
pub const CONSENT_CONTENT_KIND: &str = "consent_grant";
