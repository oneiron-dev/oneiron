//! Read-side inbox grouping projection, member classification, and dial surfacing.

use sha2::{Digest, Sha256};

use crate::dreamer_attempt_payload::decode_dreamer_attempt_payload;
use crate::gate_reason::GateReasonCode;
use crate::plugin_section_predicate::PREDICATE_PLUGIN_SECTION_INSTALL;
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::claim_predicate::PREDICATE_CONFLICT_OPEN;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

use crate::inbox::model::INBOX_REASON_CHECKER_PREFIX;
use crate::inbox::model::INBOX_RUN_BRIEF_INTENT_KEY;
use crate::inbox::model::INBOX_SUBCLUSTER_MIN_MEMBERS;
use crate::inbox::model::InboxCheckInException;
use crate::inbox::model::InboxExceptionClass;
use crate::inbox::model::InboxPointerRow;
use crate::inbox::model::InboxReviewDial;
use crate::inbox::model::InboxSubCluster;
use crate::inbox::model::VERB_CLASS_CONFLICT;
use crate::inbox::model::VERB_CLASS_NEW_CLAIM;
use crate::inbox::model::VERB_CLASS_UPDATE;

/// Semantic claim hash for cross-run duplicate collapse. The consent
/// binding (`diff_handle`) hashes the exact stored body, whose evidence
/// carries the writing actor and run provenance — so re-proposals of the
/// same fact by a later run would never match it. This hash keeps the claim
/// identity (predicate, subject, value, world, scope, validity) and drops
/// the per-write stamps.
pub fn inbox_claim_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    let mut normalized = body.clone();
    normalized.approval = ClaimApprovalStatus::Proposed;
    normalized.lifecycle = ClaimLifecycleStatus::Active;
    normalized.set_confidence(1.0, None);
    normalized.salience = None;
    normalized.evidence = None;
    normalized.source = None;
    normalized.stale = false;
    let encoded = crate::write_envelope::claim_body::encode_claim_body(&normalized)?;
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.inbox.claim_hash.v1");
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

pub fn run_brief_intent(input: &rmpv::Value) -> Option<String> {
    let rmpv::Value::Map(entries) = input else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        if key.as_str() != Some(INBOX_RUN_BRIEF_INTENT_KEY) {
            return None;
        }
        let intent = value.as_str()?.trim();
        (!intent.is_empty()).then(|| intent.to_owned())
    })
}

/// The dial rule, stated exactly.
///
/// `ApproveAll` is spelled as an explicit match over the non-waivable classes
/// rather than a single `contains`: manifest-critical and plugin-install rows
/// both REQUIRE an owner decision, and listing them here is what stops a
/// future class from being waived by accident.
pub fn member_surfaces(dial: InboxReviewDial, classes: &[InboxExceptionClass]) -> bool {
    match dial {
        InboxReviewDial::ReviewEverything => true,
        InboxReviewDial::ExceptionsOnly => !classes.is_empty(),
        InboxReviewDial::ApproveAll => classes.iter().any(|class| {
            matches!(
                class,
                InboxExceptionClass::ManifestCritical | InboxExceptionClass::PluginInstall
            )
        }),
    }
}

pub fn sub_cluster_key(body: &ClaimBody) -> String {
    match body.subject {
        ClaimSubject::Entity(subject) => format!("entity:{}", subject.to_hex()),
        ClaimSubject::Edge { .. } => {
            let theme = body.predicate.split('.').next().unwrap_or("misc");
            format!("theme:{theme}")
        }
    }
}

pub fn group_headline(
    intent: Option<&str>,
    new_claims: usize,
    updates: usize,
    conflicts: usize,
) -> String {
    let mut parts = Vec::new();
    if new_claims > 0 {
        parts.push(format!(
            "{new_claims} new claim{}",
            if new_claims == 1 { "" } else { "s" }
        ));
    }
    if updates > 0 {
        parts.push(format!(
            "{updates} update{}",
            if updates == 1 { "" } else { "s" }
        ));
    }
    if conflicts > 0 {
        parts.push(format!(
            "{conflicts} conflict{}",
            if conflicts == 1 { "" } else { "s" }
        ));
    }
    let counts = if parts.is_empty() {
        "no open proposals".to_owned()
    } else {
        parts.join(", ")
    };
    match intent {
        Some(intent) => format!("{intent}: {counts}"),
        None => format!("Dreamer run: {counts}"),
    }
}
