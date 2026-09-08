//! ONE-1887 surfaced-failure card composer and QA validators.

use super::failure_card_validation::{require_diagnosed_route, require_thread_membership};
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::failure_ladder::{
    BlockedReportRef, FailureClass, HealerRepairRoute, RetryLineagePathology, RetryOrdinal,
    failure_card_ref, failure_case_ref,
};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::run_tree::{RunTree, RunTreeFailureDiagram, mark_run_tree_failure};
use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

// ── ONE-1887 surfaced-failure card data contract ────────────────────────────
//
// Consumer-neutral ENGINE data only. The renderer/surface lane decides how to
// draw the loom-style diagram; this contract identifies the failing node and
// exposes the references an interactive Q&A needs. There are deliberately no
// pixels, no layout, no localized copy, and no downstream product names here.

/// The only schema constant this card carries.
pub const SURFACED_FAILURE_CARD_SCHEMA_VERSION: u16 = 1;

/// Where the healer's diagnosis stands when the card is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureDiagnosisState {
    /// A configured healer has the case but has not answered yet.
    NotRun,
    /// The scope's healer slot is explicitly reserved. This is a first-class
    /// state, never a generic failure string and never [`Self::NotRun`].
    ReservedHealerSlot,
    Diagnosed(HealerRepairRoute),
}

/// One referenced Q&A message. The body stays in the MESSAGE record; the card
/// never inlines a replacement transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerQaEntryRef {
    /// Lowercase-hex MESSAGE EntityId spelling.
    pub message_ref: String,
    /// Lowercase-hex witnessed author EntityId spelling.
    pub actor_ref: String,
    pub occurred_at: u64,
}

/// The reference-backed healer/human Q&A feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerQaFeed {
    /// Lowercase-hex thread EntityId spelling.
    pub thread_ref: String,
    #[serde(default)]
    pub entries: Vec<HealerQaEntryRef>,
}

/// The typed human surface for one terminalized failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfacedFailureCard {
    pub schema_version: u16,
    /// Lowercase-hex deterministic failure-card correlation key.
    pub card_ref: String,
    /// Lowercase-hex deterministic failure-case correlation key.
    pub case_ref: String,
    pub failure_class: FailureClass,
    /// Always 0 for permanent/ambiguous by policy; never computed from lineage
    /// for those classes.
    pub consecutive_transients: u16,
    #[serde(default)]
    pub pathology: Option<RetryLineagePathology>,
    pub diagram: RunTreeFailureDiagram,
    pub diagnosis: FailureDiagnosisState,
    #[serde(default)]
    pub blocked_reports: Vec<BlockedReportRef>,
    pub qa: HealerQaFeed,
}

/// Caller input for [`surfaced_failure_card`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfacedFailureCardInput {
    /// Caller-trusted classification context from the failure ladder.
    /// No typed classification is stored on the attempt; lineage and failure
    /// prose cannot authenticate this class. This door checks consistency only.
    pub failure_class: FailureClass,
    pub consecutive_transients: u16,
    pub pathology: Option<RetryLineagePathology>,
    /// Caller-trusted policy bound for validating the ordinal and complete optional pathology.
    /// Must equal the max_consecutive_transients supplied to the failure ladder.
    /// No stored policy authority exists here to verify the caller's chosen bound.
    pub retry_lineage_limit: NonZeroU16,
    pub tree: RunTree,
    pub failing_attempt_id: AttemptId,
    /// Expected pre-fail checkpoint from caller-trusted lease context.
    /// This card door does not authenticate the lease or resolve a checkpoint store.
    pub pre_fail_checkpoint_ref: EntityId,
    pub diagnosis: FailureDiagnosisState,
    pub blocked_reports: Vec<BlockedReportRef>,
    pub qa: HealerQaFeed,
}

/// Composes the typed surfaced-failure card.
///
/// `card_ref`/`case_ref` are MINTED here from `failing_attempt_id` through the
/// pinned domain-separated derivation — never accepted as free caller strings.
/// The transient count and complete optional pathology must match the same
/// bounded stored lineage; a present pathology also requires Ambiguous + zero
/// transients. The caller must supply the same policy bound used by the ladder,
/// including for `None`.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the marker does not name exactly one rendered
/// node, when a ref is not hex, when a `message_ref` does not resolve to a live
/// MESSAGE, when membership or authorship does not hold, when `occurred_at`
/// disagrees with the message's `occurred_start`, when a permanent/ambiguous
/// failure carries a nonzero transient count, when a transient count differs from
/// the bounded ordinal, when the failing attempt is missing or not stored as Failed,
/// when the optional pathology does not match the bounded lineage, when a present
/// pathology does not carry the Ambiguous class, or when a diagnosed repair has
/// noncanonical refs or mismatched agent/pre-fail checkpoint bindings.
pub fn surfaced_failure_card(
    vault: &Vault,
    input: SurfacedFailureCardInput,
) -> Result<SurfacedFailureCard> {
    if matches!(
        input.failure_class,
        FailureClass::Permanent | FailureClass::Ambiguous
    ) && input.consecutive_transients != 0
    {
        return Err(Error::InvalidConfig(
            "permanent/ambiguous failure cards require zero consecutive_transients".to_owned(),
        ));
    }
    if input.pathology.is_some()
        && (input.failure_class != FailureClass::Ambiguous || input.consecutive_transients != 0)
    {
        return Err(Error::InvalidConfig(
            "pathology failure cards require Ambiguous and zero consecutive_transients".to_owned(),
        ));
    }
    let walk = crate::failure_ladder::retry_lineage_ordinal(
        vault,
        input.failing_attempt_id,
        input.retry_lineage_limit,
    )?;
    let actual_pathology = match walk {
        RetryOrdinal::BelowLimit(ordinal) | RetryOrdinal::AtLimit(ordinal) => {
            if input.failure_class == FailureClass::Transient
                && input.consecutive_transients != ordinal.get()
            {
                return Err(Error::InvalidConfig(
                    "transient failure card consecutive_transients must match the bounded retry ordinal"
                        .to_owned(),
                ));
            }
            None
        }
        RetryOrdinal::Pathology(pathology) => Some(pathology),
    };
    if actual_pathology != input.pathology {
        return Err(Error::InvalidConfig(
            "failure card pathology must match the bounded retry lineage".to_owned(),
        ));
    }
    if let FailureDiagnosisState::Diagnosed(route) = &input.diagnosis {
        require_diagnosed_route(
            vault,
            input.failing_attempt_id,
            input.pre_fail_checkpoint_ref,
            route,
        )?;
    }
    let diagram = mark_run_tree_failure(input.tree, input.failing_attempt_id)?;
    let qa = validated_qa_feed(vault, input.qa)?;
    let blocked_reports =
        crate::failure_ladder::verified_blocked_reports(vault, &input.blocked_reports)?;
    Ok(SurfacedFailureCard {
        schema_version: SURFACED_FAILURE_CARD_SCHEMA_VERSION,
        card_ref: failure_card_ref(input.failing_attempt_id),
        case_ref: failure_case_ref(input.failing_attempt_id),
        failure_class: input.failure_class,
        consecutive_transients: input.consecutive_transients,
        pathology: input.pathology,
        diagram,
        diagnosis: input.diagnosis,
        blocked_reports,
        qa,
    })
}

/// Validates every Q&A entry against the vault, then orders the survivors
/// deterministically by `(occurred_at, message_ref)`.
fn validated_qa_feed(vault: &Vault, feed: HealerQaFeed) -> Result<HealerQaFeed> {
    let thread_ref = parse_card_ref("healer qa thread_ref", &feed.thread_ref)?;
    let mut entries = Vec::with_capacity(feed.entries.len());
    for entry in feed.entries {
        entries.push(validated_qa_entry(vault, thread_ref, entry)?);
    }
    entries.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.message_ref.cmp(&right.message_ref))
    });
    Ok(HealerQaFeed {
        thread_ref: feed.thread_ref,
        entries,
    })
}

fn validated_qa_entry(
    vault: &Vault,
    thread_ref: EntityId,
    entry: HealerQaEntryRef,
) -> Result<HealerQaEntryRef> {
    let message_ref = parse_card_ref("healer qa message_ref", &entry.message_ref)?;
    let actor_ref = parse_card_ref("healer qa actor_ref", &entry.actor_ref)?;
    let occurred_start = message_occurred_start(vault, message_ref)?;
    if occurred_start != entry.occurred_at {
        return Err(Error::InvalidConfig(
            "healer qa occurred_at must equal the message's occurred_start".to_owned(),
        ));
    }
    require_thread_membership(vault, message_ref, thread_ref)?;
    require_witnessed_author(vault, message_ref, actor_ref)?;
    Ok(entry)
}

/// Resolves `message_ref` for kind MESSAGE only and returns its
/// `occurred_start`. A header-only row is the soft-delete shell, not a
/// referenceable message.
fn message_occurred_start(vault: &Vault, message_ref: EntityId) -> Result<u64> {
    let Some(raw) = vault.get_raw(&message_ref)? else {
        return Err(Error::InvalidConfig(
            "healer qa message_ref must resolve to a stored MESSAGE".to_owned(),
        ));
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_MESSAGE || raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Err(Error::InvalidConfig(
            "healer qa message_ref must resolve to a live MESSAGE entity".to_owned(),
        ));
    }
    Ok(header.occurred_start)
}

/// Authorship is likewise an edge fact. A MESSAGE with NO `AuthoredBy` edge —
/// System-authored rows carry none by design — fails validation; surface
/// system/tool output by referencing the containing witnessed exchange instead.
fn require_witnessed_author(
    vault: &Vault,
    message_ref: EntityId,
    actor_ref: EntityId,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let author = crate::memory::sole_edge_target(
        &vault.store,
        &txn,
        &message_ref,
        EdgeKind::AuthoredBy,
        "message",
    )
    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    if author.is_none() {
        return Err(Error::InvalidConfig(
            "healer qa message_ref carries no AuthoredBy witness".to_owned(),
        ));
    }
    if author == Some(actor_ref) {
        return Ok(());
    }
    Err(Error::InvalidConfig(
        "healer qa actor_ref is not the message's witnessed author".to_owned(),
    ))
}

pub(super) fn parse_card_ref(context: &str, value: &str) -> Result<EntityId> {
    EntityId::from_hex(value).map_err(|_| {
        Error::InvalidConfig(format!("{context} must be a hex-encoded EntityId string"))
    })
}
