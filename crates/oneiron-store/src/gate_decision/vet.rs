//! Gate-decision record, notice, and receipt-reason validators.

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::gate_decision::types::GATE_DECISION_LEDGER_VERSION;
use crate::gate_decision::types::GATE_DECISION_LEDGER_VERSION_REDACTED;
use crate::gate_decision::types::GATE_DIFF_HANDLE_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_BODY_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_PLANE_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN;
use crate::gate_decision::types::GATE_SYSTEM_NOTICE_VERSION_MAX_LEN;
use crate::gate_decision::types::GateSystemNoticeRecord;

/// Whether a gate system notice is well-formed enough to sit in the ledger.
///
/// READ PATH TOO, not just the append path: `decode_gate_decision` runs this
/// over rows already on disk, so tightening it makes a non-conforming row
/// UNREADABLE (`CorruptedIndex`), not merely unwritable. That is the intended
/// reading — a notice attributing a verdict to a plane that does not exist is
/// corrupt whenever it is found — and it costs nothing today because no writer
/// in this crate can produce one, which is why `GATE_DECISION_LEDGER_VERSION`
/// does not move. Loosen-then-tighten here without checking the decode path
/// again and a real vault stops opening.
pub fn valid_gate_system_notice_record(notice: &GateSystemNoticeRecord) -> bool {
    valid_gate_notice_token(&notice.notice_type, 64)
        && !notice.channel.trim().is_empty()
        && notice.channel.len() <= 64
        && valid_gate_notice_token(&notice.voice, 32)
        && valid_gate_notice_token(&notice.audience, 32)
        && !notice.body.trim().is_empty()
        && notice.body.len() <= GATE_SYSTEM_NOTICE_BODY_MAX_LEN
        && notice.row_ref.as_deref().is_none_or(|row_ref| {
            !row_ref.trim().is_empty() && row_ref.len() <= GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN
        })
        && notice.setting_change_offer.as_ref().is_none_or(|offer| {
            !offer.label.trim().is_empty()
                && offer.label.len() <= GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN
                && !offer.target.trim().is_empty()
                && offer.target.len() <= GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN
        })
        && notice
            .policy_plane
            .as_deref()
            .is_none_or(valid_gate_notice_plane)
        && valid_gate_notice_plane_attribution(
            notice.policy_plane.as_deref(),
            notice.policy_version.as_deref(),
            notice.docs_url.as_deref(),
        )
        && valid_gate_notice_attribution(
            notice.policy_version.as_deref(),
            GATE_SYSTEM_NOTICE_VERSION_MAX_LEN,
        )
        && valid_gate_notice_attribution(
            notice.docs_url.as_deref(),
            GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
        )
}

/// The policy planes a gate system notice may be attributed to.
///
/// Spelled as literals rather than read off `PolicyPlane::as_str`: `store` sits
/// UNDER `policy_model` in the crate's layering (policy_model imports store,
/// never the reverse), so the ledger guard cannot depend on the enum it
/// mirrors.
pub const GATE_SYSTEM_NOTICE_PLANE_TOKENS: [&str; 2] = [
    GATE_SYSTEM_NOTICE_PLANE_OWNER,
    GATE_SYSTEM_NOTICE_PLANE_HOSTED,
];

/// The vault owner's own policy. It is not a published document, so a notice
/// attributed to it names no version and links to nothing.
const GATE_SYSTEM_NOTICE_PLANE_OWNER: &str = "owner_policy";

/// A hosted service's legal policy. It is a published, versioned document, so
/// a notice attributed to it always names the version it was decided under.
const GATE_SYSTEM_NOTICE_PLANE_HOSTED: &str = "hosted_legal";

/// Attribution has to match the plane that produced it, which is the contract
/// the record's own field docs state.
///
/// With no plane, the notice is not a policy verdict: `policy_version` names
/// the version of SOMETHING and `docs_url` points at the document that
/// SOMETHING publishes, so with no plane named the record says a rule was cited
/// without saying whose. The owner plane has no versioned document to name or
/// link to. The hosted legal plane always decides under a named version — a
/// hosted notice without one cannot be traced back to the text that produced
/// it. Every writer already holds all three; they are written down here so the
/// ledger holds them too.
fn valid_gate_notice_plane_attribution(
    plane: Option<&str>,
    policy_version: Option<&str>,
    docs_url: Option<&str>,
) -> bool {
    match plane {
        None | Some(GATE_SYSTEM_NOTICE_PLANE_OWNER) => {
            policy_version.is_none() && docs_url.is_none()
        }
        Some(GATE_SYSTEM_NOTICE_PLANE_HOSTED) => policy_version.is_some(),
        // An unpublished plane is rejected by `valid_gate_notice_plane`; there
        // is no attribution shape to hold it to here.
        Some(_) => false,
    }
}

/// A plane must be one of the two the policy planes publish — not merely a
/// well-formed token. Any `snake_case` string passing here would let a writer
/// attribute a verdict to a plane that does not exist, and a reader has no way
/// to tell that from a real one.
fn valid_gate_notice_plane(plane: &str) -> bool {
    valid_gate_notice_token(plane, GATE_SYSTEM_NOTICE_PLANE_MAX_LEN)
        && GATE_SYSTEM_NOTICE_PLANE_TOKENS.contains(&plane)
}

fn valid_gate_notice_attribution(value: Option<&str>, max_len: usize) -> bool {
    value.is_none_or(|value| !value.trim().is_empty() && value.len() <= max_len)
}

fn valid_gate_notice_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn valid_gate_receipt_reason(reason: &str) -> bool {
    if reason.starts_with("tripwire_normal_") {
        return crate::diagnostic_record::normal_baseline::normal_baseline_predicate(reason)
            .is_some();
    }
    if let Some(rest) = reason.strip_prefix("gate.allow.") {
        return !rest.is_empty()
            && rest.len() <= GATE_RECEIPT_REASON_MAX_LEN
            && rest.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
            });
    }

    // Policy-row IDs are bounded, lowercase manifest tokens. Keep them exact
    // on the durable receipt, not a lossy hash; only these three shapes enter
    // the new family. A malformed identifier cannot poison a ledger read.
    if let Some(row) = reason
        .strip_prefix("policy_row_")
        .or_else(|| reason.strip_prefix("policy_precedence_row_"))
    {
        return !row.is_empty()
            && reason.len() <= GATE_RECEIPT_REASON_MAX_LEN
            && row.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'.' | b'-')
            });
    }
    if reason == "policy_precedence_shipped_default" {
        return true;
    }

    // Accepted receipt-reason prefix FAMILIES (everything else is rejected):
    // counterparty_* (OF-347 contact/consent), connector_key_* and
    // effector_budget_* (OF-277 GOV-01 status wall / budget exhaustion),
    // comm_send_override_* (ONE-1752 comm.send_override decision source;
    // blueprint SPINE-COMM/ONE-1752 Leg 4 item 8),
    // charter_* (GOV-10 drift / never-list), connector_manifest_drift
    // (OF-189), checker_* (ONE-1296 host
    // auto-check hold). The charset and length rules below apply to every
    // family.
    //
    // Adding a family LOOSENS the read path too, so a row an older binary
    // would have called corrupt now decodes. That direction is safe for
    // existing bytes — every row already on disk still vets exactly as before
    // — and the receipt-family ABI-pin rule on [`STORAGE_ABI_VERSION`] binds
    // the VERSION constants, none of which move here.
    !reason.is_empty()
        && reason.len() <= GATE_RECEIPT_REASON_MAX_LEN
        && (reason.starts_with("counterparty_")
            || reason.starts_with("connector_key_")
            || reason.starts_with("effector_budget_")
            || reason.starts_with("comm_send_override_")
            || matches!(
                reason,
                "connector_manifest_drift" | "connector_manifest_stale"
            )
            || reason.starts_with("charter_")
            || reason.starts_with(GATE_RECEIPT_REASON_CHECKER_PREFIX))
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Renders one host auto-checker hold reason as a receipt reason THIS ledger
/// accepts, or `None` when the host's text carries no surviving token
/// (ONE-1296).
///
/// The gate-decision receipt is a closed token vocabulary, not a free-text
/// field: `valid_gate_receipt_reason` runs on the append path AND the decode
/// path, so a host reason like `"checker: hedged verdict"` written verbatim
/// makes the row unwritable and, were it ever persisted, unreadable —
/// `CorruptedIndex("gate decision ledger")`. A host must not be able to reach
/// that state by returning ordinary prose, so the engine RENDERS the reason
/// rather than trusting it: every non-alphanumeric run collapses to a single
/// `_`, ASCII letters lowercase, and the result is truncated to fit the
/// family prefix inside [`GATE_RECEIPT_REASON_MAX_LEN`].
///
/// The WHY survives in readable form — `"hedged: low confidence"` becomes
/// `checker_hedged_low_confidence` — which is the point: an owner reading a
/// held write still sees what the host objected to, not merely that something
/// did. The family prefix is the ENGINE's and is always applied, so host text
/// that already says "checker" simply renders after it.
///
/// POSTCONDITION: every `Some` value returned here satisfies
/// [`valid_gate_receipt_reason`]. Keep that true if either side moves.
#[must_use]
pub fn checker_hold_receipt_reason(reason: &str) -> Option<String> {
    let budget = GATE_RECEIPT_REASON_MAX_LEN - GATE_RECEIPT_REASON_CHECKER_PREFIX.len();
    let mut slug = String::with_capacity(budget);
    for character in reason.chars() {
        if slug.len() >= budget {
            break;
        }
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('_') {
            // Separator runs — including non-ASCII, which carries no token the
            // charset can keep — collapse to one `_`, and a leading one never
            // starts the slug.
            slug.push('_');
        }
    }
    let slug = slug.trim_end_matches('_');
    if slug.is_empty() {
        return None;
    }
    Some(format!("{GATE_RECEIPT_REASON_CHECKER_PREFIX}{slug}"))
}

const GATE_RECEIPT_REASON_MAX_LEN: usize = 128;

/// Receipt-reason family carrying a host auto-checker's hold reasons
/// (ONE-1296). The only producer is [`checker_hold_receipt_reason`], which
/// lives beside the vet on purpose: a host reason is FREE TEXT, and free text
/// reaching this field unrendered is what makes a row unwritable AND
/// unreadable.
const GATE_RECEIPT_REASON_CHECKER_PREFIX: &str = "checker_";
