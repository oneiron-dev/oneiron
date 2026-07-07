//! Unified receipt-family query surface over existing receipt emitters.
//!
//! RS1 is intentionally a projection over existing event substrates. This
//! module does not mint a new receipt store and does not change emitter schema.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::access_grant::{AccessGrant, AccessGrantScope, decode_access_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::error::{Error, Result};
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::outbound::OutboundIntent;
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, decode_standing_outbound_grant_body,
};
use crate::store::{
    ChannelIdentityLifecycleReceiptRecord, GateDecisionRecord, GateSystemNoticeRecord,
    PendingGateConsentRecord,
};
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, EntityId,
    companion::{
        CompanionLifecycleEvent, CompanionRecord, CompanionScope, CompanionSubject,
        decode_companion_record_body,
    },
};

const DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
const MAX_RECEIPT_QUERY_SCAN: usize = 100_000;
const RECEIPT_VIEW_COMPONENT: &str = "receipt_view";
const FIELD_JOB_REF: &str = "job_ref";
const FIELD_BRIEF_REF: &str = "brief_ref";
const FIELD_RUN_REF: &str = "run_ref";
const FIELD_INTENT_REF: &str = "intent_ref";
const FIELD_PARENT_REF: &str = "parent_ref";
const FIELD_COUNTERPARTY_REF: &str = "counterparty_ref";
const FIELD_IDENTITY_REF: &str = "identity_ref";
const FIELD_CHANNEL_IDENTITY_REF: &str = "channel_identity_ref";
const FIELD_RECEIVING_IDENTITY_REF: &str = "receiving_identity_ref";
const FIELD_GRANT_REF: &str = "grant_ref";
const FIELD_BUNDLE_REF: &str = "bundle_ref";
const FIELD_BUDGET_DEBIT: &str = "budget_debit";
const FIELD_BUDGET: &str = "budget";
const FIELD_FIRST_TOUCH: &str = "first_touch";
const FIELD_OPT_OUT: &str = "opt_out";
const FIELD_PROMO_CONSENT: &str = "promo_consent";
const SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY: &str = "third_party";
const SYSTEM_NOTICE_AUDIENCE_ALL: &str = "all";

const fn default_receipt_query_limit() -> usize {
    DEFAULT_RECEIPT_QUERY_LIMIT
}

/// Receipt family discriminator pinned by OF-367 RS1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptKind {
    /// Outbound effect receipt.
    Outbound,
    /// Gate decision/stamp receipt.
    Gate,
    /// Companion/persona identity lifecycle receipt.
    IdentityLifecycle,
    /// Scoped read/access receipt.
    ScopedRead,
    /// Share/federation receipt.
    Share,
}

impl ReceiptKind {
    /// Returns the stable query string for this receipt kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Gate => "gate",
            Self::IdentityLifecycle => "identity_lifecycle",
            Self::ScopedRead => "scoped_read",
            Self::Share => "share",
        }
    }

    /// Parses a stable receipt kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "outbound" => Some(Self::Outbound),
            "gate" => Some(Self::Gate),
            "identity_lifecycle" => Some(Self::IdentityLifecycle),
            "scoped_read" => Some(Self::ScopedRead),
            "share" => Some(Self::Share),
            _ => None,
        }
    }
}

/// Query filters for the unified receipt family.
///
/// Empty `kinds` means all supported receipt kinds. `start_at` and `end_at`
/// are inclusive Unix-second bounds over the receipt event time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQuery {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub kinds: BTreeSet<ReceiptKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_at: Option<u64>,
    #[serde(default = "default_receipt_query_limit")]
    pub limit: usize,
}

impl Default for ReceiptQuery {
    fn default() -> Self {
        Self {
            kinds: BTreeSet::new(),
            actor: None,
            outcome: None,
            job_ref: None,
            start_at: None,
            end_at: None,
            limit: DEFAULT_RECEIPT_QUERY_LIMIT,
        }
    }
}

impl ReceiptQuery {
    /// Builds an all-kind query with an explicit result limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Adds one kind filter.
    #[must_use]
    pub fn with_kind(mut self, kind: ReceiptKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// Adds an actor filter.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Adds an outcome filter.
    #[must_use]
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Adds a brief/job filter for brief-rooted receipt projections.
    #[must_use]
    pub fn with_job_ref(mut self, job_ref: impl Into<String>) -> Self {
        self.job_ref = Some(job_ref.into());
        self
    }

    /// Adds inclusive Unix-second time bounds.
    #[must_use]
    pub const fn with_time_bounds(mut self, start_at: Option<u64>, end_at: Option<u64>) -> Self {
        self.start_at = start_at;
        self.end_at = end_at;
        self
    }

    fn includes_kind(&self, kind: ReceiptKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }

    fn matches(&self, receipt: &ReceiptRecord) -> bool {
        if !self.includes_kind(receipt.receipt_kind) {
            return false;
        }
        if let Some(actor) = self.actor.as_deref()
            && receipt.actor.as_deref() != Some(actor)
            && receipt.on_behalf_of.as_deref() != Some(actor)
        {
            return false;
        }
        if let Some(outcome) = self.outcome.as_deref()
            && receipt.outcome != outcome
        {
            return false;
        }
        if let Some(start_at) = self.start_at
            && receipt.occurred_at < start_at
        {
            return false;
        }
        if let Some(end_at) = self.end_at
            && receipt.occurred_at > end_at
        {
            return false;
        }
        true
    }
}

/// One projected receipt-family row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub occurred_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_trace: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

/// Minimal OF-367/RCPT-3 seam for consumers that render receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptView {
    pub component: String,
    pub receipt: ReceiptRecord,
}

impl ReceiptView {
    #[must_use]
    pub fn new(receipt: ReceiptRecord) -> Self {
        Self {
            component: RECEIPT_VIEW_COMPONENT.to_owned(),
            receipt,
        }
    }
}

/// Query for the EF-055 pending tray lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayQuery {
    pub now: u64,
    pub limit: usize,
}

impl PendingTrayQuery {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            now: crate::unix_seconds_now(),
            limit,
        }
    }

    #[must_use]
    pub const fn at(now: u64, limit: usize) -> Self {
        Self { now, limit }
    }
}

/// One current pending ask for the logbook tray lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayAsk {
    pub claim_id: String,
    pub created_at: u64,
    pub age_secs: u64,
    pub hold_reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hold_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreamer_run_id: Option<String>,
    pub receipt_view: ReceiptView,
}

/// Brief-rooted receipt projection for the B2 RS4 project view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BriefReceiptProjection {
    pub brief_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<ReceiptProjectionRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_receipts: Vec<ReceiptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grants: Vec<ReceiptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// One run under a brief-rooted receipt projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptProjectionRun {
    pub run_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intents: Vec<ReceiptProjectionIntent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// One outbound intent under a projected run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptProjectionIntent {
    pub intent_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Per-counterparty receipt projection for "who have you contacted on my behalf".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterpartyReceiptProjection {
    pub counterparty_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_touch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt_out: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promo_consent: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Per-grant receipt projection for "this grant produced N sends".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReceiptProjection {
    pub grant_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Query for the OF-367 RS6.5 standing outbound-grants lens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantsLensQuery {
    pub limit: usize,
    pub receipt_limit_per_grant: usize,
}

impl StandingOutboundGrantsLensQuery {
    #[must_use]
    pub const fn new(limit: usize, receipt_limit_per_grant: usize) -> Self {
        Self {
            limit,
            receipt_limit_per_grant,
        }
    }
}

/// Grants-page projection over active, stale, and revoked standing grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantsLens {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<StandingOutboundGrantLensRow>,
}

/// One standing outbound-grant row for the grants page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantLensRow {
    pub grant_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_receipt_ref: Option<String>,
    pub scope_dial: String,
    pub status: String,
    pub stale: bool,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    pub receipt_join: GrantReceiptProjection,
    pub revoke_action: StandingOutboundGrantRevokeAction,
}

/// Host-interpreted one-tap revoke command for a grants lens row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantRevokeAction {
    pub command: String,
    pub grant_ref: String,
}

impl Vault {
    /// Queries the unified receipt family across existing receipt emitters.
    pub fn receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        receipt_family_query(self, &query)
    }

    /// Alias for callers that prefer verb-first query naming.
    pub fn query_receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        self.receipts(query)
    }

    /// Returns the current pending tray lane rows backed by Pending-state Gate receipts.
    pub fn pending_tray(&self, query: PendingTrayQuery) -> Result<Vec<PendingTrayAsk>> {
        pending_tray_query(self, query)
    }

    /// Resolves a stale pending ask by emitting a `let_go` receipt and removing it from the tray.
    pub fn let_go_pending_ask(&self, claim_id: &EntityId) -> Result<Option<ReceiptRecord>> {
        self.let_go_pending_ask_at(claim_id, crate::unix_seconds_now())
    }

    /// Testable variant of [`Vault::let_go_pending_ask`] with an explicit event time.
    pub fn let_go_pending_ask_at(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<Option<ReceiptRecord>> {
        let emitted = self.with_write_txn(|wtxn| {
            self.store
                .let_go_pending_gate_consent_in_txn(wtxn, claim_id, now)
        })?;
        Ok(emitted.as_ref().map(gate_decision_receipt))
    }

    /// Computes the brief-rooted receipt projection from the unified family.
    pub fn receipt_projection_by_brief(
        &self,
        brief_ref: impl Into<String>,
        query: ReceiptQuery,
    ) -> Result<BriefReceiptProjection> {
        Ok(project_receipts_by_brief(brief_ref, self.receipts(query)?))
    }

    /// Computes per-counterparty receipt projections from the unified family.
    pub fn receipt_projections_by_counterparty(
        &self,
        query: ReceiptQuery,
    ) -> Result<Vec<CounterpartyReceiptProjection>> {
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        let receipts = self.receipts(projection_scan_query(query))?;
        let contact_records = counterparty_contact_records_for_receipts(self, &receipts)?;
        Ok(project_receipts_by_counterparty_with_contacts(
            receipts,
            &contact_records,
        ))
    }

    /// Computes the per-grant receipt projection from the unified family.
    pub fn receipt_projection_by_grant(
        &self,
        grant_ref: impl Into<String>,
        query: ReceiptQuery,
    ) -> Result<GrantReceiptProjection> {
        let limit = query.limit;
        if limit == 0 {
            return Ok(project_receipts_by_grant_limited(
                grant_ref,
                Vec::new(),
                limit,
            ));
        }
        Ok(project_receipts_by_grant_limited(
            grant_ref,
            self.receipts(projection_scan_query(query))?,
            limit,
        ))
    }

    /// Computes the standing outbound-grants lens behind the logbook.
    pub fn standing_outbound_grants_lens(
        &self,
        query: StandingOutboundGrantsLensQuery,
    ) -> Result<StandingOutboundGrantsLens> {
        standing_outbound_grants_lens(self, query)
    }
}

/// Builds an outbound receipt row from the OF-327 intent spine.
///
/// The helper keeps `job_ref` propagation explicit for brief-rooted runs while
/// preserving legacy compatibility: callers that pass an older intent without a
/// job ref still emit a receipt with `job_ref: None`.
#[must_use]
pub fn outbound_intent_receipt(
    receipt_id: impl Into<String>,
    intent_ref: impl Into<String>,
    intent: &OutboundIntent,
    occurred_at: u64,
    outcome: impl Into<String>,
) -> ReceiptRecord {
    let receipt_id = receipt_id.into();
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_INTENT_REF.to_owned(), intent_ref.into());
    fields.insert("verb".to_owned(), intent.verb.clone());
    fields.insert("channel".to_owned(), intent.channel.clone());
    fields.insert("target".to_owned(), intent.target.clone());
    fields.insert("intent_source".to_owned(), intent.intent_source.clone());

    ReceiptRecord {
        receipt_id,
        receipt_kind: ReceiptKind::Outbound,
        occurred_at,
        actor: Some(intent.actor.clone()),
        on_behalf_of: intent.on_behalf_of.clone(),
        outcome: outcome.into(),
        job_ref: intent.job_ref.clone(),
        trigger_ref: Some(intent.trigger_ref.clone()),
        policy_trace: Vec::new(),
        fields,
    }
}

/// Computes the brief/project receipt projection over supplied receipt rows.
///
/// This is a pure projection: it does not write grouping state. Direct
/// `job_ref`/`brief_ref` matches win, and older rows can still join the brief
/// through `trigger_ref` plus `run_ref`/`intent_ref`/`parent_ref` chain fields.
#[must_use]
pub fn project_receipts_by_brief(
    brief_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> BriefReceiptProjection {
    let brief_ref = brief_ref.into();
    let receipts = receipts.into_iter().collect::<Vec<_>>();
    let index = ReceiptProjectionIndex::new(&receipts);
    let mut builder = BriefProjectionBuilder::new(brief_ref.clone());

    for receipt in receipts {
        if index.receipt_matches_brief(&receipt, &brief_ref) {
            builder.push(receipt, &index);
        }
    }

    builder.finish()
}

/// Computes one projection per counterparty over supplied receipt rows.
#[must_use]
pub fn project_receipts_by_counterparty(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> Vec<CounterpartyReceiptProjection> {
    project_receipts_by_counterparty_with_contacts(receipts, &BTreeMap::new())
}

fn project_receipts_by_counterparty_with_contacts(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    contact_records: &BTreeMap<String, CounterpartyContactProjection>,
) -> Vec<CounterpartyReceiptProjection> {
    let mut projections = BTreeMap::<String, CounterpartyProjectionBuilder>::new();
    let mut receipts = receipts.into_iter().collect::<Vec<_>>();
    sort_receipts_newest_first(&mut receipts);

    for receipt in receipts {
        let Some(counterparty_ref) = receipt_counterparty_ref(&receipt) else {
            continue;
        };
        projections
            .entry(counterparty_ref.clone())
            .or_insert_with(|| CounterpartyProjectionBuilder::new(counterparty_ref))
            .push(receipt);
    }

    for (counterparty_ref, contact) in contact_records {
        if let Some(builder) = projections.get_mut(counterparty_ref) {
            builder.apply_contact(contact);
        }
    }

    projections
        .into_values()
        .map(CounterpartyProjectionBuilder::finish)
        .collect()
}

/// Computes the grant receipt projection over supplied receipt rows.
#[must_use]
pub fn project_receipts_by_grant(
    grant_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> GrantReceiptProjection {
    project_receipts_by_grant_limited(grant_ref, receipts, usize::MAX)
}

fn project_receipts_by_grant_limited(
    grant_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    limit: usize,
) -> GrantReceiptProjection {
    let grant_ref = grant_ref.into();
    let mut projection = GrantReceiptProjection {
        grant_ref: grant_ref.clone(),
        receipts: Vec::new(),
        budget_debit_total: 0,
    };

    for receipt in receipts {
        if receipt_matches_grant(&receipt, &grant_ref) {
            projection.budget_debit_total = projection
                .budget_debit_total
                .saturating_add(receipt_budget_debit(&receipt));
            projection.receipts.push(receipt);
        }
    }
    projection.receipts.truncate(limit);

    projection
}

fn standing_outbound_grants_lens(
    vault: &Vault,
    query: StandingOutboundGrantsLensQuery,
) -> Result<StandingOutboundGrantsLens> {
    if query.limit == 0 {
        return Ok(StandingOutboundGrantsLens { grants: Vec::new() });
    }

    let policy_floor = {
        let rtxn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?
    };
    let receipt_records = if query.receipt_limit_per_grant == 0 {
        Vec::new()
    } else {
        vault.receipts(projection_scan_query(
            ReceiptQuery::new(query.receipt_limit_per_grant)
                .with_kind(ReceiptKind::Gate)
                .with_kind(ReceiptKind::ScopedRead),
        ))?
    };

    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    scan_entities_by_type(
        vault,
        &rtxn,
        ENTITY_TYPE_OUTBOUND_GRANT,
        "outbound grant type index",
        |id, _header, body| {
            let grant = decode_standing_outbound_grant_body(body)?;
            rows.push(standing_outbound_grant_lens_row(
                id,
                &grant,
                &policy_floor,
                &receipt_records,
                query.receipt_limit_per_grant,
            ));
            Ok(())
        },
    )?;
    rows.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.grant_ref.cmp(&right.grant_ref))
    });
    rows.truncate(query.limit);
    Ok(StandingOutboundGrantsLens { grants: rows })
}

fn standing_outbound_grant_lens_row(
    id: EntityId,
    grant: &StandingOutboundGrant,
    policy_floor: &[u8; 32],
    receipt_records: &[ReceiptRecord],
    receipt_limit: usize,
) -> StandingOutboundGrantLensRow {
    let grant_ref = format!("grant:{}", id.to_hex());
    let stale = !grant.is_active_under_policy(policy_floor) && grant.revoked_at.is_none();
    StandingOutboundGrantLensRow {
        grant_ref: grant_ref.clone(),
        origin_component_id: grant.origin_component_id.clone(),
        origin_action_id: grant.origin_action_id.clone(),
        origin_receipt_ref: grant.origin_receipt_ref.clone(),
        scope_dial: grant.scope.dial_label().to_owned(),
        status: grant.status.as_str().to_owned(),
        stale,
        created_at: grant.created_at,
        last_used_at: grant.last_used_at,
        revoked_at: grant.revoked_at,
        receipt_join: project_receipts_by_grant_limited(
            grant_ref.clone(),
            receipt_records.iter().cloned(),
            receipt_limit,
        ),
        revoke_action: StandingOutboundGrantRevokeAction {
            command: "revoke_standing_outbound_grant".to_owned(),
            grant_ref,
        },
    }
}

#[derive(Debug, Default)]
struct ReceiptProjectionIndex {
    run_to_brief: BTreeMap<String, String>,
    run_to_parent_run: BTreeMap<String, String>,
    intent_to_run: BTreeMap<String, String>,
    intent_to_brief: BTreeMap<String, String>,
}

impl ReceiptProjectionIndex {
    fn new(receipts: &[ReceiptRecord]) -> Self {
        let mut index = Self::default();
        for receipt in receipts {
            let brief_ref = direct_brief_ref(receipt);
            let run_ref = direct_run_ref(receipt);
            let intent_ref = direct_intent_ref(receipt);

            if let (Some(run_ref), Some(brief_ref)) = (run_ref.as_deref(), brief_ref.as_deref()) {
                index
                    .run_to_brief
                    .entry(run_ref.to_owned())
                    .or_insert_with(|| brief_ref.to_owned());
            }
            if let (Some(intent_ref), Some(brief_ref)) =
                (intent_ref.as_deref(), brief_ref.as_deref())
            {
                index
                    .intent_to_brief
                    .entry(intent_ref.to_owned())
                    .or_insert_with(|| brief_ref.to_owned());
            }
            if let (Some(intent_ref), Some(run_ref)) = (intent_ref.as_deref(), run_ref.as_deref()) {
                index
                    .intent_to_run
                    .entry(intent_ref.to_owned())
                    .or_insert_with(|| run_ref.to_owned());
            }

            if let Some(parent_ref) = field_ref(receipt, FIELD_PARENT_REF) {
                if parent_ref.starts_with("brief:") {
                    if let Some(run_ref) = run_ref.as_deref() {
                        index
                            .run_to_brief
                            .entry(run_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                    if let Some(intent_ref) = intent_ref.as_deref() {
                        index
                            .intent_to_brief
                            .entry(intent_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                } else if parent_ref.starts_with("run:") {
                    if let Some(run_ref) = run_ref.as_deref() {
                        index
                            .run_to_parent_run
                            .entry(run_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                    if let Some(intent_ref) = intent_ref.as_deref() {
                        index
                            .intent_to_run
                            .entry(intent_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                }
            }
        }

        loop {
            let mut changed = false;
            for run_ref in index.run_to_parent_run.keys().cloned().collect::<Vec<_>>() {
                let Some(parent_run_ref) = index.run_to_parent_run.get(&run_ref) else {
                    continue;
                };
                if let Some(brief_ref) = index.run_to_brief.get(parent_run_ref).cloned()
                    && !index.run_to_brief.contains_key(&run_ref)
                {
                    index.run_to_brief.insert(run_ref, brief_ref);
                    changed = true;
                }
            }
            for intent_ref in index.intent_to_run.keys().cloned().collect::<Vec<_>>() {
                let Some(run_ref) = index.intent_to_run.get(&intent_ref) else {
                    continue;
                };
                if let Some(brief_ref) = index.run_to_brief.get(run_ref).cloned()
                    && !index.intent_to_brief.contains_key(&intent_ref)
                {
                    index.intent_to_brief.insert(intent_ref, brief_ref);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        index
    }

    fn receipt_matches_brief(&self, receipt: &ReceiptRecord, brief_ref: &str) -> bool {
        if direct_brief_ref(receipt).is_some_and(|value| refs_match(&value, brief_ref)) {
            return true;
        }
        if let Some(run_ref) = direct_run_ref(receipt)
            && self
                .run_to_brief
                .get(&run_ref)
                .is_some_and(|value| refs_match(value, brief_ref))
        {
            return true;
        }
        if let Some(intent_ref) = direct_intent_ref(receipt) {
            if self
                .intent_to_brief
                .get(&intent_ref)
                .is_some_and(|value| refs_match(value, brief_ref))
            {
                return true;
            }
            if let Some(run_ref) = self.intent_to_run.get(&intent_ref)
                && self
                    .run_to_brief
                    .get(run_ref)
                    .is_some_and(|value| refs_match(value, brief_ref))
            {
                return true;
            }
        }
        false
    }

    fn receipt_run_ref(&self, receipt: &ReceiptRecord) -> Option<String> {
        direct_run_ref(receipt).or_else(|| {
            direct_intent_ref(receipt)
                .and_then(|intent_ref| self.intent_to_run.get(&intent_ref).cloned())
        })
    }
}

#[derive(Debug)]
struct BriefProjectionBuilder {
    brief_ref: String,
    runs: BTreeMap<String, ReceiptProjectionRunBuilder>,
    direct_receipts: Vec<ReceiptRecord>,
    consent_grants: Vec<ReceiptRecord>,
    bundles: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl BriefProjectionBuilder {
    fn new(brief_ref: String) -> Self {
        Self {
            brief_ref,
            runs: BTreeMap::new(),
            direct_receipts: Vec::new(),
            consent_grants: Vec::new(),
            bundles: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, index: &ReceiptProjectionIndex) {
        let budget = receipt_budget_debit(&receipt);
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);

        if receipt_is_consent_grant(&receipt) {
            self.consent_grants.push(receipt.clone());
        }
        if receipt_is_bundle_event(&receipt) {
            self.bundles.push(receipt.clone());
        }

        let intent_ref = direct_intent_ref(&receipt);
        if let Some(run_ref) = index.receipt_run_ref(&receipt) {
            self.runs
                .entry(run_ref.clone())
                .or_insert_with(|| ReceiptProjectionRunBuilder::new(run_ref))
                .push(receipt, intent_ref, budget);
        } else {
            self.direct_receipts.push(receipt);
        }
    }

    fn finish(self) -> BriefReceiptProjection {
        BriefReceiptProjection {
            brief_ref: self.brief_ref,
            runs: self
                .runs
                .into_values()
                .map(ReceiptProjectionRunBuilder::finish)
                .collect(),
            direct_receipts: self.direct_receipts,
            consent_grants: self.consent_grants,
            bundles: self.bundles,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct ReceiptProjectionRunBuilder {
    run_ref: String,
    intents: BTreeMap<String, ReceiptProjectionIntentBuilder>,
    direct_receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl ReceiptProjectionRunBuilder {
    fn new(run_ref: String) -> Self {
        Self {
            run_ref,
            intents: BTreeMap::new(),
            direct_receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, intent_ref: Option<String>, budget: u64) {
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);
        if let Some(intent_ref) = intent_ref {
            self.intents
                .entry(intent_ref.clone())
                .or_insert_with(|| ReceiptProjectionIntentBuilder::new(intent_ref))
                .push(receipt, budget);
        } else {
            self.direct_receipts.push(receipt);
        }
    }

    fn finish(self) -> ReceiptProjectionRun {
        ReceiptProjectionRun {
            run_ref: self.run_ref,
            intents: self
                .intents
                .into_values()
                .map(ReceiptProjectionIntentBuilder::finish)
                .collect(),
            direct_receipts: self.direct_receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct ReceiptProjectionIntentBuilder {
    intent_ref: String,
    receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl ReceiptProjectionIntentBuilder {
    fn new(intent_ref: String) -> Self {
        Self {
            intent_ref,
            receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, budget: u64) {
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);
        self.receipts.push(receipt);
    }

    fn finish(self) -> ReceiptProjectionIntent {
        ReceiptProjectionIntent {
            intent_ref: self.intent_ref,
            receipts: self.receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct CounterpartyProjectionBuilder {
    counterparty_ref: String,
    first_touch: Option<String>,
    opt_out: Option<bool>,
    promo_consent: Option<bool>,
    receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl CounterpartyProjectionBuilder {
    fn new(counterparty_ref: String) -> Self {
        Self {
            counterparty_ref,
            first_touch: None,
            opt_out: None,
            promo_consent: None,
            receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord) {
        if self.first_touch.is_none()
            && let Some(first_touch) = field_ref(&receipt, FIELD_FIRST_TOUCH)
        {
            self.first_touch = Some(first_touch.to_owned());
        }
        if let Some(opt_out) = bool_field(&receipt, FIELD_OPT_OUT) {
            self.opt_out.get_or_insert(opt_out);
        }
        if let Some(promo_consent) = bool_field(&receipt, FIELD_PROMO_CONSENT) {
            self.promo_consent.get_or_insert(promo_consent);
        }
        self.budget_debit_total = self
            .budget_debit_total
            .saturating_add(receipt_budget_debit(&receipt));
        self.receipts.push(receipt);
    }

    fn apply_contact(&mut self, contact: &CounterpartyContactProjection) {
        self.first_touch = contact.first_touch.clone();
        self.opt_out = Some(contact.opt_out);
        self.promo_consent = Some(contact.promo_consent);
    }

    fn finish(self) -> CounterpartyReceiptProjection {
        CounterpartyReceiptProjection {
            counterparty_ref: self.counterparty_ref,
            first_touch: self.first_touch,
            opt_out: self.opt_out,
            promo_consent: self.promo_consent,
            receipts: self.receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

fn direct_brief_ref(receipt: &ReceiptRecord) -> Option<String> {
    receipt
        .job_ref
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| field_ref(receipt, FIELD_JOB_REF).map(str::to_owned))
        .or_else(|| field_ref(receipt, FIELD_BRIEF_REF).map(str::to_owned))
        .or_else(|| trigger_ref_with_prefix(receipt, "brief:"))
}

fn direct_run_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_RUN_REF)
        .map(str::to_owned)
        .or_else(|| trigger_ref_with_prefix(receipt, "run:"))
}

fn direct_intent_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_INTENT_REF)
        .map(str::to_owned)
        .or_else(|| trigger_ref_with_prefix(receipt, "intent:"))
}

fn receipt_counterparty_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_COUNTERPARTY_REF)
        .or_else(|| field_ref(receipt, "target"))
        .map(str::to_owned)
}

fn receipt_identity_ref(receipt: &ReceiptRecord) -> Option<EntityId> {
    [
        FIELD_CHANNEL_IDENTITY_REF,
        FIELD_RECEIVING_IDENTITY_REF,
        FIELD_IDENTITY_REF,
    ]
    .iter()
    .find_map(|key| field_ref(receipt, key).and_then(entity_ref_from_str))
}

fn receipt_matches_grant(receipt: &ReceiptRecord, grant_ref: &str) -> bool {
    field_ref(receipt, FIELD_GRANT_REF).is_some_and(|value| refs_match(value, grant_ref))
        || receipt
            .trigger_ref
            .as_deref()
            .filter(|value| value.starts_with("access_grant:") || value.starts_with("grant:"))
            .is_some_and(|value| refs_match(value, grant_ref))
}

fn receipt_is_consent_grant(receipt: &ReceiptRecord) -> bool {
    receipt.receipt_kind == ReceiptKind::ScopedRead
}

fn receipt_is_bundle_event(receipt: &ReceiptRecord) -> bool {
    field_ref(receipt, FIELD_BUNDLE_REF).is_some()
        || receipt
            .trigger_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("bundle:"))
        || field_ref(receipt, "event").is_some_and(|value| value == "bundle")
}

fn receipt_budget_debit(receipt: &ReceiptRecord) -> u64 {
    field_ref(receipt, FIELD_BUDGET_DEBIT)
        .or_else(|| field_ref(receipt, FIELD_BUDGET))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn bool_field(receipt: &ReceiptRecord, key: &str) -> Option<bool> {
    match field_ref(receipt, key)? {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn field_ref<'a>(receipt: &'a ReceiptRecord, key: &str) -> Option<&'a str> {
    receipt
        .fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn trigger_ref_with_prefix(receipt: &ReceiptRecord, prefix: &str) -> Option<String> {
    receipt
        .trigger_ref
        .as_deref()
        .filter(|value| value.starts_with(prefix))
        .map(str::to_owned)
}

fn refs_match(candidate: &str, target: &str) -> bool {
    candidate == target || strip_ref_prefix(candidate) == strip_ref_prefix(target)
}

fn strip_ref_prefix(value: &str) -> &str {
    value
        .split_once(':')
        .map_or(value, |(_prefix, suffix)| suffix)
}

fn entity_ref_from_str(value: &str) -> Option<EntityId> {
    EntityId::from_hex(strip_ref_prefix(value)).ok()
}

fn projection_scan_query(mut query: ReceiptQuery) -> ReceiptQuery {
    query.limit = MAX_RECEIPT_QUERY_SCAN;
    query
}

fn lineage_scan_query() -> ReceiptQuery {
    ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN)
}

fn sort_receipts_newest_first(records: &mut [ReceiptRecord]) {
    records.sort_by(|left, right| {
        right
            .occurred_at
            .cmp(&left.occurred_at)
            .then_with(|| left.receipt_kind.cmp(&right.receipt_kind))
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
}

fn finalize_receipt_query_records(
    mut records: Vec<ReceiptRecord>,
    query: &ReceiptQuery,
    lineage_records: Option<&[ReceiptRecord]>,
) -> Vec<ReceiptRecord> {
    sort_receipts_newest_first(&mut records);
    if let Some(job_ref) = query.job_ref.as_deref() {
        let index = ReceiptProjectionIndex::new(lineage_records.unwrap_or(&records));
        records.retain(|receipt| index.receipt_matches_brief(receipt, job_ref));
    }
    records.truncate(query.limit);
    records
}

#[derive(Debug, Clone)]
struct CounterpartyContactProjection {
    first_touch: Option<String>,
    first_touch_created_at: u64,
    opt_out: bool,
    promo_consent: bool,
}

impl CounterpartyContactProjection {
    fn new(contact: &CounterpartyContactRecord) -> Self {
        Self {
            first_touch: Some(contact.first_touch.as_str().to_owned()),
            first_touch_created_at: contact.created_at,
            opt_out: contact.is_opted_out(),
            promo_consent: contact.promo_consent,
        }
    }

    fn merge(&mut self, contact: &CounterpartyContactRecord) {
        if contact.created_at < self.first_touch_created_at {
            self.first_touch = Some(contact.first_touch.as_str().to_owned());
            self.first_touch_created_at = contact.created_at;
        }
        self.opt_out |= contact.is_opted_out();
        self.promo_consent &= contact.promo_consent;
    }
}

fn counterparty_contact_records_for_receipts(
    vault: &Vault,
    receipts: &[ReceiptRecord],
) -> Result<BTreeMap<String, CounterpartyContactProjection>> {
    let mut wanted_by_identity = BTreeMap::<EntityId, BTreeMap<String, BTreeSet<String>>>::new();
    for receipt in receipts {
        let (Some(counterparty_ref), Some(identity_ref)) = (
            receipt_counterparty_ref(receipt),
            receipt_identity_ref(receipt),
        ) else {
            continue;
        };
        wanted_by_identity
            .entry(identity_ref)
            .or_default()
            .entry(counterparty_ref.trim().to_owned())
            .or_default()
            .insert(counterparty_ref);
    }

    let mut contacts = BTreeMap::<String, CounterpartyContactProjection>::new();
    for (identity_ref, wanted_counterparties) in wanted_by_identity {
        for (_contact_id, contact) in vault.counterparty_contacts_for_identity(&identity_ref)? {
            let Some(counterparty_refs) = wanted_counterparties.get(&contact.counterparty) else {
                continue;
            };
            for counterparty_ref in counterparty_refs {
                contacts
                    .entry(counterparty_ref.clone())
                    .and_modify(|projection| projection.merge(&contact))
                    .or_insert_with(|| CounterpartyContactProjection::new(&contact));
            }
        }
    }
    Ok(contacts)
}

fn receipt_family_query(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let records = collect_receipt_records(vault, query)?;
    let lineage_records = if query.job_ref.is_some() {
        Some(collect_receipt_records(vault, &lineage_scan_query())?)
    } else {
        None
    };
    Ok(finalize_receipt_query_records(
        records,
        query,
        lineage_records.as_deref(),
    ))
}

fn collect_receipt_records(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut records = Vec::new();
    if query.includes_kind(ReceiptKind::Gate) {
        records.extend(gate_receipts(vault, query)?);
    }

    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(channel_identity_lifecycle_receipts(vault, query)?);
    }

    let rtxn = vault.store.env.read_txn()?;
    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(companion_lifecycle_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::ScopedRead) {
        records.extend(access_grant_receipts(vault, &rtxn, query)?);
        records.extend(outbound_grant_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::Share) {
        records.extend(federation_share_receipts(vault, &rtxn, query)?);
    }

    Ok(records)
}

fn gate_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for decision in vault.store.gate_decisions(MAX_RECEIPT_QUERY_SCAN)? {
        let receipt = gate_decision_receipt(&decision);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn gate_decision_receipt(record: &GateDecisionRecord) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("content_kind".to_owned(), record.content_kind.clone());
    fields.insert(
        "policy_manifest_version".to_owned(),
        record.policy_manifest_version.clone(),
    );
    fields.insert("diff_handle".to_owned(), hex_lower(&record.diff_handle));
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&record.read_frontier_hash),
    );
    if let Some(receipt_reason) = record.receipt_reasons.first() {
        fields.insert("receipt_reason".to_owned(), receipt_reason.clone());
    }
    if record.receipt_reasons.len() > 1 {
        fields.insert(
            "receipt_reasons".to_owned(),
            record.receipt_reasons.join(","),
        );
    }
    if let Some(grant_ref) = record.grant_ref.as_ref() {
        fields.insert(FIELD_GRANT_REF.to_owned(), grant_ref.clone());
    }
    if let Some(notice) = select_gate_system_notice_for_receipt(&record.system_notices) {
        fields.insert("system_notice_type".to_owned(), notice.notice_type.clone());
        fields.insert("system_notice_channel".to_owned(), notice.channel.clone());
        fields.insert("system_notice_voice".to_owned(), notice.voice.clone());
        fields.insert("system_notice_audience".to_owned(), notice.audience.clone());
        fields.insert("system_notice".to_owned(), notice.body.clone());
    }

    let mut policy_trace = record.reason_codes.clone();
    policy_trace.extend(record.receipt_reasons.clone());
    policy_trace.extend(
        record
            .system_notices
            .iter()
            .map(|notice| format!("gate.system_notice.{}", notice.notice_type)),
    );

    ReceiptRecord {
        receipt_id: format!("gate:{}", record.decision_id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        job_ref: None,
        trigger_ref: record
            .claim_id
            .map(|id| format!("claim:{}", hex_lower(&id))),
        policy_trace,
        fields,
    }
}

fn select_gate_system_notice_for_receipt(
    notices: &[GateSystemNoticeRecord],
) -> Option<&GateSystemNoticeRecord> {
    notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
        .or_else(|| {
            notices
                .iter()
                .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_ALL)
        })
        .or_else(|| notices.first())
}

fn pending_tray_query(vault: &Vault, query: PendingTrayQuery) -> Result<Vec<PendingTrayAsk>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let rtxn = vault.store.env.read_txn()?;
    let mut asks = Vec::new();
    for pending in vault
        .store
        .pending_gate_consents_in_txn(&rtxn, query.limit)?
    {
        let Some(decision) = vault
            .store
            .gate_decision_in_txn(&rtxn, pending.decision_id)?
        else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        if decision.outcome != "pending" {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        asks.push(pending_tray_ask(&pending, &decision, query.now));
    }
    Ok(asks)
}

fn pending_tray_ask(
    pending: &PendingGateConsentRecord,
    decision: &GateDecisionRecord,
    now: u64,
) -> PendingTrayAsk {
    let receipt = gate_decision_receipt(decision);
    let hold_reasons = pending.reason_codes.clone();
    let hold_reason = hold_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| "gate.pending".to_owned());
    PendingTrayAsk {
        claim_id: hex_lower(&pending.claim_id),
        created_at: pending.created_at,
        age_secs: now.saturating_sub(pending.created_at),
        hold_reason,
        hold_reasons,
        dreamer_run_id: pending.dreamer_run_id.clone(),
        receipt_view: ReceiptView::new(receipt),
    }
}

fn companion_lifecycle_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_COMPANION_REGISTER,
        "companion register type index",
        |id, header, body| {
            let record = decode_companion_record_body(body)?;
            for (index, event) in record.lifecycle_events.iter().enumerate() {
                let receipt =
                    companion_lifecycle_receipt(id, &record, *event, index, header.learned_at);
                if query.matches(&receipt) {
                    receipts.push(receipt);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn companion_lifecycle_receipt(
    id: EntityId,
    record: &CompanionRecord,
    event: CompanionLifecycleEvent,
    event_index: usize,
    learned_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        "actor_class".to_owned(),
        record.provenance.actor_class.gate_actor_class().to_owned(),
    );
    fields.insert(
        "source".to_owned(),
        record.provenance.source.as_str().to_owned(),
    );
    fields.insert(
        "approval".to_owned(),
        record.provenance.approval.as_str().to_owned(),
    );
    fields.insert("record_kind".to_owned(), record.kind().as_str().to_owned());
    fields.insert(
        "record_lifecycle".to_owned(),
        record.lifecycle.as_str().to_owned(),
    );
    fields.insert("learned_at".to_owned(), learned_at.to_string());
    append_companion_scope_fields(&mut fields, &record.scope);
    append_companion_subject_fields(&mut fields, &record.subject);

    ReceiptRecord {
        receipt_id: format!(
            "identity_lifecycle:{}:{}:{}",
            id.to_hex(),
            event.kind.as_str(),
            event_index
        ),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: event.at,
        actor: Some(record.provenance.actor_ref.to_hex()),
        on_behalf_of: None,
        outcome: event.kind.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("entity:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn channel_identity_lifecycle_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for record in vault
        .store
        .channel_identity_lifecycle_receipts(MAX_RECEIPT_QUERY_SCAN)?
    {
        let receipt = channel_identity_lifecycle_receipt(&record);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn channel_identity_lifecycle_receipt(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("verb".to_owned(), record.verb.clone());
    fields.insert("intent_kind".to_owned(), record.intent_kind.clone());
    fields.insert("channel".to_owned(), record.channel.clone());
    fields.insert(
        "address_or_handle".to_owned(),
        record.address_or_handle.clone(),
    );
    fields.insert("state".to_owned(), record.state.clone());
    fields.insert(
        "owner_visible_state".to_owned(),
        record.owner_visible_state.clone(),
    );
    fields.insert(
        "outbound_closed".to_owned(),
        record.outbound_closed.to_string(),
    );
    fields.insert(
        "identity_retiring".to_owned(),
        record.identity_retiring.to_string(),
    );
    if let Some(mode) = record.fulfillment_mode.as_ref() {
        fields.insert("fulfillment_mode".to_owned(), mode.clone());
    }
    if let Some(until) = record.quarantine_until {
        fields.insert("quarantine_until".to_owned(), until.to_string());
    }
    if let Some(decision_id) = record.gate_decision_id {
        fields.insert(
            "gate_decision_ref".to_owned(),
            format!("gate:{}", decision_id.to_hex()),
        );
    }

    ReceiptRecord {
        receipt_id: crate::channel_identity_lifecycle::lifecycle_receipt_ref(record.receipt_id),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        job_ref: None,
        trigger_ref: Some(format!("entity:{}", hex_lower(&record.identity_id))),
        policy_trace: Vec::new(),
        fields,
    }
}

fn access_grant_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_ACCESS_GRANT,
        "access grant type index",
        |id, _header, body| {
            let grant = decode_access_grant_body(body)?;
            let created = access_grant_receipt(id, &grant, grant.created_at, "active", "created");
            if query.matches(&created) {
                receipts.push(created);
            }
            if let Some(revoked_at) = grant.revoked_at {
                let revoked = access_grant_receipt(id, &grant, revoked_at, "revoked", "revoked");
                if query.matches(&revoked) {
                    receipts.push(revoked);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn access_grant_receipt(
    id: EntityId,
    grant: &AccessGrant,
    occurred_at: u64,
    outcome: &str,
    event_name: &str,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("status".to_owned(), grant.status.as_str().to_owned());
    fields.insert(
        "capability".to_owned(),
        grant.capability.as_str().to_owned(),
    );
    append_access_grant_scope_fields(&mut fields, grant.scope);

    ReceiptRecord {
        receipt_id: format!("scoped_read:{}:{event_name}", id.to_hex()),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at,
        actor: Some(grant.principal_ref.to_hex()),
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("access_grant:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn outbound_grant_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_OUTBOUND_GRANT,
        "outbound grant type index",
        |id, _header, body| {
            let grant = decode_standing_outbound_grant_body(body)?;
            let created = outbound_grant_receipt(id, &grant, grant.created_at, "active", "created");
            if query.matches(&created) {
                receipts.push(created);
            }
            if let Some(revoked_at) = grant.revoked_at {
                let revoked = outbound_grant_receipt(id, &grant, revoked_at, "revoked", "revoked");
                if query.matches(&revoked) {
                    receipts.push(revoked);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn outbound_grant_receipt(
    id: EntityId,
    grant: &StandingOutboundGrant,
    occurred_at: u64,
    outcome: &str,
    event_name: &str,
) -> ReceiptRecord {
    let grant_ref = format!("grant:{}", id.to_hex());
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_GRANT_REF.to_owned(), grant_ref.clone());
    fields.insert("status".to_owned(), grant.status.as_str().to_owned());
    fields.insert("scope_dial".to_owned(), grant.scope.dial_label().to_owned());
    fields.insert(
        "origin_component_id".to_owned(),
        grant.origin_component_id.clone(),
    );
    fields.insert(
        "origin_action_id".to_owned(),
        grant.origin_action_id.clone(),
    );
    fields.insert(
        "binding_diff_handle".to_owned(),
        hex_lower(&grant.binding_diff_handle),
    );
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&grant.read_frontier_hash),
    );
    if let Some(origin_receipt_ref) = grant.origin_receipt_ref.as_ref() {
        fields.insert("origin_receipt_ref".to_owned(), origin_receipt_ref.clone());
    }
    if let Some(last_used_at) = grant.last_used_at {
        fields.insert("last_used_at".to_owned(), last_used_at.to_string());
    }
    append_outbound_grant_scope_fields(&mut fields, &grant.scope);

    ReceiptRecord {
        receipt_id: format!("scoped_read:{}:{event_name}", grant_ref),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at,
        actor: Some(grant.principal_ref.clone()),
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: outbound_grant_job_ref(&grant.scope),
        trigger_ref: Some(grant_ref),
        policy_trace: Vec::new(),
        fields,
    }
}

fn federation_share_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        "federation grant type index",
        |id, header, body| {
            let grant = decode_federation_grant_body(body)?;
            let receipt = federation_share_receipt(id, &grant, header.occurred_start);
            if query.matches(&receipt) {
                receipts.push(receipt);
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn federation_share_receipt(
    id: EntityId,
    grant: &FederationGrant,
    occurred_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("role".to_owned(), grant.role.as_str().to_owned());
    fields.insert("preset".to_owned(), grant.preset.as_str().to_owned());
    append_federation_scope_fields(&mut fields, grant.scope);

    ReceiptRecord {
        receipt_id: format!("share:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at,
        actor: Some(grant.member_ref.to_hex()),
        on_behalf_of: None,
        outcome: "granted".to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("federation_grant:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn scan_entities_by_type(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity_type: u8,
    context: &'static str,
    mut visit: impl FnMut(EntityId, EntityMetadataHeader, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut scanned = 0_usize;
    for entry in vault.store.type_index.prefix_iter(txn, &[entity_type])? {
        let (key, _) = entry?;
        if key.first().copied() != Some(entity_type) {
            return Err(Error::CorruptedIndex(context));
        }
        let id = entity_id_from_type_index_key(key, context)?;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex(context));
        };
        let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex(context))?;
        if header.entity_type != entity_type {
            return Err(Error::CorruptedIndex(context));
        }
        visit(id, header, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        scanned = scanned.saturating_add(1);
        if scanned >= MAX_RECEIPT_QUERY_SCAN {
            break;
        }
    }
    Ok(())
}

fn entity_id_from_type_index_key(key: &[u8], context: &'static str) -> Result<EntityId> {
    if key.len() != 1 + ENTITY_ID_LEN {
        return Err(Error::CorruptedIndex(context));
    }
    EntityId::from_bytes(
        key[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex(context))?,
    )
    .map_err(|_| Error::CorruptedIndex(context))
}

fn append_companion_scope_fields(fields: &mut BTreeMap<String, String>, scope: &CompanionScope) {
    match scope {
        CompanionScope::Neutral => {
            fields.insert("scope".to_owned(), "neutral".to_owned());
        }
        CompanionScope::Personal { person_ref } => {
            fields.insert("scope".to_owned(), "personal".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
        }
        CompanionScope::SharedVault { vault_id } => {
            fields.insert("scope".to_owned(), "shared_vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
    }
}

fn append_companion_subject_fields(
    fields: &mut BTreeMap<String, String>,
    subject: &CompanionSubject,
) {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            fields.insert("subject".to_owned(), "persona".to_owned());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => {
            fields.insert("subject".to_owned(), "relationship".to_owned());
            fields.insert("source_ref".to_owned(), source_ref.to_hex());
            fields.insert("target_ref".to_owned(), target_ref.to_hex());
        }
    }
}

fn append_access_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: AccessGrantScope,
) {
    match scope {
        AccessGrantScope::CompanionProfile {
            person_ref,
            persona_ref,
        } => {
            fields.insert("scope".to_owned(), "companion_profile".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
    }
}

fn append_outbound_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: &StandingOutboundGrantScope,
) {
    match scope {
        StandingOutboundGrantScope::Contact { contact_ref } => {
            fields.insert("scope".to_owned(), "contact".to_owned());
            fields.insert("contact_ref".to_owned(), contact_ref.clone());
        }
        StandingOutboundGrantScope::VerbClass { verb_class } => {
            fields.insert("scope".to_owned(), "verb_class".to_owned());
            fields.insert("verb_class".to_owned(), verb_class.clone());
        }
        StandingOutboundGrantScope::Channel { channel } => {
            fields.insert("scope".to_owned(), "channel".to_owned());
            fields.insert("channel".to_owned(), channel.clone());
        }
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            fields.insert("scope".to_owned(), "brief_verb_class".to_owned());
            fields.insert(FIELD_BRIEF_REF.to_owned(), brief_ref.clone());
            fields.insert("verb_class".to_owned(), verb_class.clone());
        }
    }
}

fn outbound_grant_job_ref(scope: &StandingOutboundGrantScope) -> Option<String> {
    match scope {
        StandingOutboundGrantScope::BriefVerbClass { brief_ref, .. } => Some(brief_ref.clone()),
        _ => None,
    }
}

fn append_federation_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: FederationGrantScope,
) {
    match scope {
        FederationGrantScope::Vault { vault_id } => {
            fields.insert("scope".to_owned(), "vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_grant::AccessGrant;
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
        encode_federation_grant_body,
    };
    use crate::store::{GateDecisionId, PendingGateConsentRecord, Store};
    use crate::types::{
        ENTITY_TYPE_REDACTION_AUDIT, EdgeActorClass, HnswConfig, VaultConfig, WriteActor,
        WriteEnvelope, WriteProvenance,
        companion::{
            CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
        },
    };

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), test_config())?;
        Ok((dir, vault))
    }

    fn entity(seed: u8) -> EntityId {
        let mut bytes = [seed; ENTITY_ID_LEN];
        bytes[0] = seed.max(1);
        EntityId::from_bytes(bytes).expect("test entity id")
    }

    fn field_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn projected_receipt(
        receipt_id: &str,
        receipt_kind: ReceiptKind,
        occurred_at: u64,
        outcome: &str,
        job_ref: Option<&str>,
        trigger_ref: Option<&str>,
        fields: &[(&str, &str)],
    ) -> ReceiptRecord {
        ReceiptRecord {
            receipt_id: receipt_id.to_owned(),
            receipt_kind,
            occurred_at,
            actor: Some("agent-alpha".to_owned()),
            on_behalf_of: Some("owner".to_owned()),
            outcome: outcome.to_owned(),
            job_ref: job_ref.map(str::to_owned),
            trigger_ref: trigger_ref.map(str::to_owned),
            policy_trace: Vec::new(),
            fields: field_map(fields),
        }
    }

    fn append_gate_decision(
        vault: &Vault,
        created_at: u64,
        actor: &str,
        outcome: &str,
        reason: &str,
    ) -> Result<GateDecisionId> {
        append_gate_decision_for_claim(vault, created_at, actor, outcome, reason, entity(0x41))
    }

    fn append_gate_decision_for_claim(
        vault: &Vault,
        created_at: u64,
        actor: &str,
        outcome: &str,
        reason: &str,
        claim_id: EntityId,
    ) -> Result<GateDecisionId> {
        let decision_id = GateDecisionId::now();
        vault.with_write_txn(|wtxn| {
            vault.store.append_gate_decision_in_txn(
                wtxn,
                &GateDecisionRecord {
                    version: 0,
                    decision_id,
                    created_at,
                    outcome: outcome.to_owned(),
                    reason_codes: vec![reason.to_owned()],
                    receipt_reasons: Vec::new(),
                    system_notices: Vec::new(),
                    actor_class: "agent".to_owned(),
                    actor_ref: Some(actor.to_owned()),
                    content_kind: "external_effect".to_owned(),
                    policy_manifest_version: "test-policy".to_owned(),
                    claim_id: Some(*claim_id.as_bytes()),
                    grant_ref: None,
                    diff_handle: vec![0xA5],
                    read_frontier_hash: [0xB6; 32],
                },
            )
        })?;
        Ok(decision_id)
    }

    fn gate_system_notice(audience: &str, body: &str) -> GateSystemNoticeRecord {
        GateSystemNoticeRecord {
            notice_type: "policy_block".to_owned(),
            channel: "EF-196/OF-221".to_owned(),
            voice: "system".to_owned(),
            audience: audience.to_owned(),
            body: body.to_owned(),
            row_ref: None,
            setting_change_offer: None,
        }
    }

    fn append_pending_gate_consent(
        vault: &Vault,
        created_at: u64,
        actor: &str,
        claim_id: EntityId,
        reason: &str,
        dreamer_run_id: Option<&str>,
    ) -> Result<GateDecisionId> {
        let decision_id =
            append_gate_decision_for_claim(vault, created_at, actor, "pending", reason, claim_id)?;
        vault.with_write_txn(|wtxn| {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &PendingGateConsentRecord {
                    version: 0,
                    claim_id: *claim_id.as_bytes(),
                    decision_id,
                    created_at,
                    diff_handle: vec![0xA5],
                    read_frontier_hash: [0xB6; 32],
                    reason_codes: vec![reason.to_owned()],
                    dreamer_run_id: dreamer_run_id.map(str::to_owned),
                },
            )
        })?;
        Ok(decision_id)
    }

    fn provenance(actor: EntityId) -> CompanionProvenance {
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Agent),
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("receipt fixture")).unwrap(),
            ClaimApprovalStatus::Approved,
        );
        CompanionProvenance::from_envelope(&envelope)
    }

    fn companion_record(actor: EntityId) -> CompanionRecord {
        CompanionRecord::persona(
            CompanionScope::neutral(),
            entity(0x51),
            rmpv::Value::from("persona"),
            provenance(actor),
            CompanionExportClassification::Portable,
        )
    }

    fn put_federation_grant(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
        let grant = FederationGrant::new(
            FederationGrantScope::vault(7),
            entity(0x61),
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        );
        let body = encode_federation_grant_body(&grant)?;
        vault.with_write_txn(|wtxn| {
            let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
            payload.push(ENTITY_TYPE_FEDERATION_GRANT);
            payload.extend_from_slice(&learned_at.to_be_bytes());
            payload.extend_from_slice(&learned_at.to_be_bytes());
            payload.extend_from_slice(&learned_at.to_be_bytes());
            payload.extend_from_slice(&body);
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;

            let type_key = Store::encode_type_key(ENTITY_TYPE_FEDERATION_GRANT, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            let temporal_key = Store::encode_temporal_key(learned_at, &id);
            vault
                .store
                .temporal_occurred_start
                .put(wtxn, &temporal_key, &[])?;
            vault.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
            Ok(())
        })
    }

    fn put_redaction_floor_receipt(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + 4);
        payload.push(ENTITY_TYPE_REDACTION_AUDIT);
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(b"seal");
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            let temporal_key = Store::encode_temporal_key(learned_at, &id);
            vault
                .store
                .temporal_occurred_start
                .put(wtxn, &temporal_key, &[])?;
            vault.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
            Ok(())
        })
    }

    #[test]
    fn receipt_query_deserializes_missing_limit_with_default() -> Result<()> {
        let query: ReceiptQuery = serde_json::from_str(r#"{"outcome":"held"}"#)
            .map_err(|_| Error::InvariantViolation("receipt query json fixture"))?;
        assert_eq!(query.limit, DEFAULT_RECEIPT_QUERY_LIMIT);
        assert_eq!(query.outcome.as_deref(), Some("held"));
        assert_eq!(query.job_ref, None);
        Ok(())
    }

    #[test]
    fn receipt_record_job_ref_is_optional_for_legacy_json() -> Result<()> {
        let receipt: ReceiptRecord = serde_json::from_str(
            r#"{
                "receipt_id": "outbound:intent:legacy",
                "receipt_kind": "outbound",
                "occurred_at": 10,
                "outcome": "delivered_to_channel",
                "trigger_ref": "run:ad-hoc"
            }"#,
        )
        .map_err(|_| Error::InvariantViolation("receipt json fixture"))?;

        assert_eq!(receipt.job_ref, None);
        Ok(())
    }

    #[test]
    fn receipt_query_job_ref_filter_matches_legacy_projection_fields() {
        let receipt = projected_receipt(
            "outbound:intent:legacy",
            ReceiptKind::Outbound,
            10,
            "delivered_to_channel",
            None,
            Some("intent:legacy"),
            &[("brief_ref", "brief:party")],
        );
        let unrelated = projected_receipt(
            "outbound:intent:other",
            ReceiptKind::Outbound,
            11,
            "delivered_to_channel",
            None,
            Some("intent:other"),
            &[("brief_ref", "brief:other")],
        );

        let filtered = finalize_receipt_query_records(
            vec![unrelated, receipt],
            &ReceiptQuery::new(10).with_job_ref("party"),
            None,
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].receipt_id, "outbound:intent:legacy");
    }

    #[test]
    fn receipt_query_job_ref_filter_chain_walks_before_limit() {
        let records = vec![
            projected_receipt(
                "outbound:intent:unrelated",
                ReceiptKind::Outbound,
                50,
                "delivered_to_channel",
                None,
                Some("intent:unrelated"),
                &[("brief_ref", "brief:other")],
            ),
            projected_receipt(
                "gate:run-planning",
                ReceiptKind::Gate,
                10,
                "started",
                None,
                Some("run:planning"),
                &[("parent_ref", "brief:party")],
            ),
            projected_receipt(
                "outbound:intent:invite-aki",
                ReceiptKind::Outbound,
                11,
                "delivered_to_channel",
                None,
                Some("intent:invite-aki"),
                &[("run_ref", "run:planning"), ("budget_debit", "4")],
            ),
        ];

        let filtered = finalize_receipt_query_records(
            records,
            &ReceiptQuery::new(2).with_job_ref("party"),
            None,
        );

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].receipt_id, "outbound:intent:invite-aki");
        assert_eq!(filtered[1].receipt_id, "gate:run-planning");
    }

    #[test]
    fn receipt_query_job_ref_filter_uses_unfiltered_lineage_index() {
        let lineage = vec![
            projected_receipt(
                "gate:run-planning",
                ReceiptKind::Gate,
                10,
                "started",
                None,
                Some("run:planning"),
                &[("parent_ref", "brief:party")],
            ),
            projected_receipt(
                "outbound:intent:invite-aki",
                ReceiptKind::Outbound,
                11,
                "delivered_to_channel",
                None,
                Some("intent:invite-aki"),
                &[("run_ref", "run:planning"), ("budget_debit", "4")],
            ),
        ];
        let visible = vec![lineage[1].clone()];

        let filtered = finalize_receipt_query_records(
            visible,
            &ReceiptQuery::new(10)
                .with_kind(ReceiptKind::Outbound)
                .with_outcome("delivered_to_channel")
                .with_job_ref("party"),
            Some(&lineage),
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].receipt_id, "outbound:intent:invite-aki");
    }

    #[test]
    fn outbound_intent_receipt_propagates_job_ref() {
        let intent = OutboundIntent {
            actor: "agent-alpha".to_owned(),
            on_behalf_of: Some("owner".to_owned()),
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "kenji@example.com".to_owned(),
            intent_source: "brief_run".to_owned(),
            trigger_ref: "intent:invite-kenji".to_owned(),
            job_ref: Some("brief:party".to_owned()),
        };

        let receipt = outbound_intent_receipt(
            "outbound:intent:invite-kenji",
            "intent:invite-kenji",
            &intent,
            42,
            "delivered_to_channel",
        );

        assert_eq!(receipt.receipt_kind, ReceiptKind::Outbound);
        assert_eq!(receipt.actor.as_deref(), Some("agent-alpha"));
        assert_eq!(receipt.on_behalf_of.as_deref(), Some("owner"));
        assert_eq!(receipt.job_ref.as_deref(), Some("brief:party"));
        assert_eq!(receipt.trigger_ref.as_deref(), Some("intent:invite-kenji"));
        assert_eq!(
            receipt.fields.get("intent_ref").map(String::as_str),
            Some("intent:invite-kenji")
        );
        assert_eq!(
            receipt.fields.get("target").map(String::as_str),
            Some("kenji@example.com")
        );
    }

    #[test]
    fn receipt_query_returns_mixed_kinds_and_filters() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        append_gate_decision(
            &vault,
            10,
            "agent-alpha",
            "pending",
            "gate.pending.actor_ceiling",
        )?;

        let identity_actor = entity(0x50);
        vault.create_companion_record(&entity(0x52), &companion_record(identity_actor), 20)?;

        let access_grant =
            AccessGrant::companion_profile_read(entity(0x60), entity(0x62), entity(0x63), 30);
        vault.create_access_grant(&entity(0x64), &access_grant)?;
        put_federation_grant(&vault, entity(0x65), 40)?;

        let receipts = vault.receipts(ReceiptQuery::new(10))?;
        let kinds: BTreeSet<_> = receipts
            .iter()
            .map(|receipt| receipt.receipt_kind)
            .collect();
        assert!(kinds.contains(&ReceiptKind::Gate));
        assert!(kinds.contains(&ReceiptKind::IdentityLifecycle));
        assert!(kinds.contains(&ReceiptKind::ScopedRead));
        assert!(kinds.contains(&ReceiptKind::Share));

        let gate = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        assert_eq!(gate.len(), 1);
        assert_eq!(gate[0].actor.as_deref(), Some("agent-alpha"));

        let by_actor = vault.receipts(ReceiptQuery::new(10).with_actor(identity_actor.to_hex()))?;
        assert_eq!(by_actor.len(), 1);
        assert_eq!(by_actor[0].receipt_kind, ReceiptKind::IdentityLifecycle);

        let by_outcome = vault.receipts(ReceiptQuery::new(10).with_outcome("active"))?;
        assert_eq!(by_outcome.len(), 1);
        assert_eq!(by_outcome[0].receipt_kind, ReceiptKind::ScopedRead);

        let recent = vault.receipts(ReceiptQuery::new(10).with_time_bounds(Some(35), None))?;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].receipt_kind, ReceiptKind::Share);
        Ok(())
    }

    #[test]
    fn gate_receipt_system_notice_selection_is_order_independent() {
        let decision = GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::now(),
            created_at: 10,
            outcome: "block".to_owned(),
            reason_codes: vec!["gate.policy_model.block".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: vec![
                gate_system_notice("owner", "owner row details"),
                gate_system_notice(SYSTEM_NOTICE_AUDIENCE_ALL, "all audience notice"),
                gate_system_notice(
                    SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY,
                    "third-party safe notice",
                ),
            ],
            actor_class: "policy_model".to_owned(),
            actor_ref: Some("agent-alpha".to_owned()),
            content_kind: "outbound_content".to_owned(),
            policy_manifest_version: "test-policy".to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: vec![0xA5],
            read_frontier_hash: [0xB6; 32],
        };

        let receipt = gate_decision_receipt(&decision);
        assert_eq!(
            receipt
                .fields
                .get("system_notice_audience")
                .map(String::as_str),
            Some(SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
        );
        assert_eq!(
            receipt.fields.get("system_notice").map(String::as_str),
            Some("third-party safe notice")
        );

        let notices = vec![
            gate_system_notice("owner", "owner row details"),
            gate_system_notice(SYSTEM_NOTICE_AUDIENCE_ALL, "all audience notice"),
        ];
        assert_eq!(
            select_gate_system_notice_for_receipt(&notices).map(|notice| notice.audience.as_str()),
            Some(SYSTEM_NOTICE_AUDIENCE_ALL)
        );

        let notices = vec![gate_system_notice("owner", "owner row details")];
        assert_eq!(
            select_gate_system_notice_for_receipt(&notices).map(|notice| notice.audience.as_str()),
            Some("owner")
        );
    }

    #[test]
    fn receipt_query_filters_negative_space_outcomes_identically() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        append_gate_decision(&vault, 10, "agent-alpha", "delivered", "gate.allow")?;
        append_gate_decision(
            &vault,
            11,
            "agent-alpha",
            "held",
            "gate.pending.external_effect_authority",
        )?;
        append_gate_decision(
            &vault,
            12,
            "agent-beta",
            "let_go",
            "gate.pending.external_effect_authority",
        )?;

        let held = vault.receipts(ReceiptQuery::new(10).with_outcome("held"))?;
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].outcome, "held");

        let let_go = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
        assert_eq!(let_go.len(), 1);
        assert_eq!(let_go[0].actor.as_deref(), Some("agent-beta"));

        let delivered = vault.receipts(ReceiptQuery::new(10).with_outcome("delivered"))?;
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].outcome, "delivered");
        Ok(())
    }

    #[test]
    fn pending_tray_returns_current_asks_with_age_hold_reason_and_receipt_view() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        let old_claim = entity(0x81);
        let recent_claim = entity(0x82);
        let gone_claim = entity(0x83);
        append_pending_gate_consent(
            &vault,
            10,
            "agent-alpha",
            old_claim,
            "gate.pending.external_effect_authority",
            Some("dreamer-run-a"),
        )?;
        append_pending_gate_consent(
            &vault,
            30,
            "agent-beta",
            recent_claim,
            "gate.pending.source_trust",
            None,
        )?;
        append_gate_decision_for_claim(
            &vault,
            40,
            "agent-gamma",
            "let_go",
            "gate.pending.gap_decayed",
            gone_claim,
        )?;

        let asks = vault.pending_tray(PendingTrayQuery::at(50, 10))?;
        assert_eq!(asks.len(), 2);

        let old = &asks[0];
        assert_eq!(old.claim_id, old_claim.to_hex());
        assert_eq!(old.created_at, 10);
        assert_eq!(old.age_secs, 40);
        assert_eq!(old.hold_reason, "gate.pending.external_effect_authority");
        assert_eq!(
            old.hold_reasons,
            vec!["gate.pending.external_effect_authority"]
        );
        assert_eq!(old.dreamer_run_id.as_deref(), Some("dreamer-run-a"));
        assert_eq!(old.receipt_view.component, RECEIPT_VIEW_COMPONENT);
        assert_eq!(old.receipt_view.receipt.receipt_kind, ReceiptKind::Gate);
        assert_eq!(old.receipt_view.receipt.outcome, "pending");
        assert_eq!(
            old.receipt_view.receipt.actor.as_deref(),
            Some("agent-alpha")
        );
        assert_eq!(
            old.receipt_view.receipt.trigger_ref.as_deref(),
            Some(format!("claim:{}", old_claim.to_hex()).as_str())
        );

        let recent = &asks[1];
        assert_eq!(recent.claim_id, recent_claim.to_hex());
        assert_eq!(recent.age_secs, 20);
        assert_eq!(recent.hold_reason, "gate.pending.source_trust");
        assert!(
            asks.iter()
                .all(|ask| ask.claim_id.as_str() != gone_claim.to_hex())
        );
        Ok(())
    }

    #[test]
    fn let_go_pending_ask_emits_receipt_before_clearing_tray() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        let claim_id = entity(0x84);
        append_pending_gate_consent(
            &vault,
            10,
            "agent-alpha",
            claim_id,
            "gate.pending.external_effect_authority",
            Some("dreamer-run-a"),
        )?;

        let emitted = vault
            .let_go_pending_ask_at(&claim_id, 99)?
            .expect("age-out must emit a receipt");
        assert_eq!(emitted.receipt_kind, ReceiptKind::Gate);
        assert_eq!(emitted.outcome, "let_go");
        assert_eq!(emitted.actor.as_deref(), Some("agent-alpha"));
        assert_eq!(
            emitted.trigger_ref.as_deref(),
            Some(format!("claim:{}", claim_id.to_hex()).as_str())
        );
        assert_eq!(emitted.policy_trace, vec!["gate.pending.gap_decayed"]);

        assert!(
            vault
                .pending_tray(PendingTrayQuery::at(100, 10))?
                .is_empty()
        );
        let let_go = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
        assert_eq!(let_go.len(), 1);
        assert_eq!(let_go[0], emitted);

        assert!(vault.let_go_pending_ask_at(&claim_id, 120)?.is_none());
        let still_one = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
        assert_eq!(still_one.len(), 1);
        Ok(())
    }

    #[test]
    fn receipt_query_never_returns_floor_redaction_receipts() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        let floor_id = entity(0x70);
        put_redaction_floor_receipt(&vault, floor_id, 50)?;
        append_gate_decision(
            &vault,
            10,
            "agent-alpha",
            "pending",
            "gate.pending.actor_ceiling",
        )?;

        let all = vault.receipts(ReceiptQuery::new(10))?;
        assert!(
            all.iter()
                .all(|receipt| !receipt.receipt_id.contains(&floor_id.to_hex()))
        );

        for kind in [
            ReceiptKind::Outbound,
            ReceiptKind::Gate,
            ReceiptKind::IdentityLifecycle,
            ReceiptKind::ScopedRead,
            ReceiptKind::Share,
        ] {
            let rows = vault.receipts(ReceiptQuery::new(10).with_kind(kind))?;
            assert!(
                rows.iter()
                    .all(|receipt| !receipt.receipt_id.contains(&floor_id.to_hex()))
            );
        }
        Ok(())
    }

    #[test]
    fn brief_projection_returns_multi_session_party_tree_and_budget() {
        let receipts = vec![
            projected_receipt(
                "outbound:intent:invite-yuki",
                ReceiptKind::Outbound,
                100,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:invite-yuki"),
                &[
                    ("run_ref", "run:planning"),
                    ("intent_ref", "intent:invite-yuki"),
                    ("counterparty_ref", "person:yuki"),
                    ("grant_ref", "party-grant"),
                    ("budget_debit", "3"),
                ],
            ),
            projected_receipt(
                "outbound:intent:invite-kenji",
                ReceiptKind::Outbound,
                101,
                "held",
                Some("brief:party"),
                Some("intent:invite-kenji"),
                &[
                    ("run_ref", "run:planning"),
                    ("intent_ref", "intent:invite-kenji"),
                    ("counterparty_ref", "person:kenji"),
                    ("grant_ref", "party-grant"),
                    ("budget_debit", "2"),
                ],
            ),
            projected_receipt(
                "outbound:intent:invite-mika",
                ReceiptKind::Outbound,
                102,
                "declined",
                Some("brief:party"),
                Some("intent:invite-mika"),
                &[
                    ("run_ref", "run:followup"),
                    ("intent_ref", "intent:invite-mika"),
                    ("counterparty_ref", "person:mika"),
                    ("first_touch", "user_introduction"),
                    ("opt_out", "false"),
                    ("promo_consent", "true"),
                    ("budget_debit", "1"),
                ],
            ),
            projected_receipt(
                "gate:bundle-party",
                ReceiptKind::Gate,
                103,
                "approved",
                Some("brief:party"),
                Some("bundle:party-invites"),
                &[
                    ("run_ref", "run:planning"),
                    ("bundle_ref", "bundle:party-invites"),
                    ("event", "bundle"),
                ],
            ),
            projected_receipt(
                "scoped_read:party-grant:created",
                ReceiptKind::ScopedRead,
                90,
                "active",
                Some("brief:party"),
                Some("access_grant:party-grant"),
                &[("grant_ref", "party-grant")],
            ),
        ];

        let projection = project_receipts_by_brief("brief:party", receipts.clone());

        assert_eq!(projection.brief_ref, "brief:party");
        assert_eq!(projection.runs.len(), 2);
        assert_eq!(projection.consent_grants.len(), 1);
        assert_eq!(projection.bundles.len(), 1);
        assert_eq!(projection.budget_debit_total, 6);

        let planning = projection
            .runs
            .iter()
            .find(|run| run.run_ref == "run:planning")
            .expect("planning run");
        let outcomes = planning
            .intents
            .iter()
            .flat_map(|intent| {
                intent
                    .receipts
                    .iter()
                    .map(|receipt| receipt.outcome.as_str())
            })
            .collect::<BTreeSet<_>>();
        assert!(outcomes.contains("delivered_to_channel"));
        assert!(outcomes.contains("held"));
        assert_eq!(
            planning.direct_receipts[0].trigger_ref.as_deref(),
            Some("bundle:party-invites")
        );

        let counterparties = project_receipts_by_counterparty(receipts.clone());
        let mika = counterparties
            .iter()
            .find(|projection| projection.counterparty_ref == "person:mika")
            .expect("mika counterparty projection");
        assert_eq!(mika.first_touch.as_deref(), Some("user_introduction"));
        assert_eq!(mika.opt_out, Some(false));
        assert_eq!(mika.promo_consent, Some(true));

        let grant = project_receipts_by_grant("party-grant", receipts);
        let sends = grant
            .receipts
            .iter()
            .filter(|receipt| receipt.receipt_kind == ReceiptKind::Outbound)
            .count();
        assert_eq!(sends, 2);
        assert_eq!(grant.budget_debit_total, 5);
    }

    #[test]
    fn projections_avoid_grant_trigger_collisions_and_consent_false_positive() {
        let receipts = vec![
            projected_receipt(
                "gate:bundle-party-grant",
                ReceiptKind::Gate,
                100,
                "approved",
                Some("brief:party"),
                Some("bundle:party-grant"),
                &[("bundle_ref", "bundle:party-grant")],
            ),
            projected_receipt(
                "outbound:grant-trigger",
                ReceiptKind::Outbound,
                101,
                "delivered_to_channel",
                Some("brief:party"),
                Some("access_grant:party-grant"),
                &[("grant_ref", "party-grant"), ("budget_debit", "2")],
            ),
        ];

        let grant = project_receipts_by_grant("party-grant", receipts.clone());
        assert_eq!(grant.receipts.len(), 1);
        assert_eq!(grant.receipts[0].receipt_id, "outbound:grant-trigger");
        assert_eq!(grant.budget_debit_total, 2);

        let brief = project_receipts_by_brief("brief:party", receipts);
        assert_eq!(brief.bundles.len(), 1);
        assert!(brief.consent_grants.is_empty());
    }

    #[test]
    fn counterparty_projection_preserves_latest_contact_flags() {
        let receipts = vec![
            projected_receipt(
                "outbound:older",
                ReceiptKind::Outbound,
                10,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:older"),
                &[
                    ("counterparty_ref", "kenji@example.com"),
                    ("opt_out", "true"),
                    ("promo_consent", "false"),
                ],
            ),
            projected_receipt(
                "outbound:newer",
                ReceiptKind::Outbound,
                20,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:newer"),
                &[
                    ("counterparty_ref", "kenji@example.com"),
                    ("opt_out", "false"),
                    ("promo_consent", "true"),
                ],
            ),
        ];

        let projections = project_receipts_by_counterparty(receipts);

        assert_eq!(projections.len(), 1);
        assert_eq!(projections[0].opt_out, Some(false));
        assert_eq!(projections[0].promo_consent, Some(true));
    }

    #[test]
    fn counterparty_projection_joins_contact_records() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        let identity_ref = entity(0x91);
        let contact =
            CounterpartyContactRecord::user_introduction(identity_ref, "kenji@example.com", 10)?
                .with_promo_consent(true, 11)?
                .opted_out(CounterpartyOptOutReason::Stop, 12)?;
        vault.create_counterparty_contact(&entity(0x92), &contact)?;
        let identity_ref_hex = identity_ref.to_hex();
        let receipts = vec![projected_receipt(
            "outbound:joined-contact",
            ReceiptKind::Outbound,
            20,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:joined-contact"),
            &[
                ("counterparty_ref", "kenji@example.com"),
                ("channel_identity_ref", identity_ref_hex.as_str()),
                ("budget_debit", "2"),
            ],
        )];

        let contacts = counterparty_contact_records_for_receipts(&vault, &receipts)?;
        let projections = project_receipts_by_counterparty_with_contacts(receipts, &contacts);

        assert_eq!(projections.len(), 1);
        assert_eq!(
            projections[0].first_touch.as_deref(),
            Some("user_introduction")
        );
        assert_eq!(projections[0].opt_out, Some(true));
        assert_eq!(projections[0].promo_consent, Some(true));
        assert_eq!(projections[0].budget_debit_total, 2);
        Ok(())
    }

    #[test]
    fn counterparty_projection_combines_multi_identity_contacts_conservatively() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        let identity_a = entity(0xA1);
        let identity_b = entity(0xA2);
        let opted_out =
            CounterpartyContactRecord::inbound_first(identity_a, "kenji@example.com", 5)?
                .opted_out(CounterpartyOptOutReason::Stop, 8)?;
        let consented =
            CounterpartyContactRecord::user_introduction(identity_b, "kenji@example.com", 10)?
                .with_promo_consent(true, 11)?;
        vault.create_counterparty_contact(&entity(0xA3), &opted_out)?;
        vault.create_counterparty_contact(&entity(0xA4), &consented)?;
        let identity_a_hex = identity_a.to_hex();
        let identity_b_hex = identity_b.to_hex();
        let receipts = vec![
            projected_receipt(
                "outbound:identity-a",
                ReceiptKind::Outbound,
                20,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:identity-a"),
                &[
                    ("counterparty_ref", "kenji@example.com"),
                    ("channel_identity_ref", identity_a_hex.as_str()),
                ],
            ),
            projected_receipt(
                "outbound:identity-b",
                ReceiptKind::Outbound,
                21,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:identity-b"),
                &[
                    ("counterparty_ref", "kenji@example.com"),
                    ("channel_identity_ref", identity_b_hex.as_str()),
                ],
            ),
        ];

        let contacts = counterparty_contact_records_for_receipts(&vault, &receipts)?;
        let projections = project_receipts_by_counterparty_with_contacts(receipts, &contacts);

        assert_eq!(projections.len(), 1);
        assert_eq!(projections[0].first_touch.as_deref(), Some("inbound_first"));
        assert_eq!(projections[0].opt_out, Some(true));
        assert_eq!(projections[0].promo_consent, Some(false));
        Ok(())
    }

    #[test]
    fn grant_projection_filters_before_projection_limit() {
        let receipts = vec![
            projected_receipt(
                "outbound:unrelated-newer",
                ReceiptKind::Outbound,
                50,
                "delivered_to_channel",
                Some("brief:other"),
                Some("intent:unrelated"),
                &[("grant_ref", "other-grant"), ("budget_debit", "9")],
            ),
            projected_receipt(
                "outbound:grant-newer",
                ReceiptKind::Outbound,
                20,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:grant-newer"),
                &[("grant_ref", "party-grant"), ("budget_debit", "3")],
            ),
            projected_receipt(
                "outbound:grant-older",
                ReceiptKind::Outbound,
                10,
                "delivered_to_channel",
                Some("brief:party"),
                Some("intent:grant-older"),
                &[("grant_ref", "party-grant"), ("budget_debit", "2")],
            ),
        ];

        let projection = project_receipts_by_grant_limited("party-grant", receipts, 1);

        assert_eq!(projection.receipts.len(), 1);
        assert_eq!(projection.receipts[0].receipt_id, "outbound:grant-newer");
        assert_eq!(projection.budget_debit_total, 5);
    }

    #[test]
    fn brief_projection_chain_walks_when_job_ref_is_absent() {
        let receipts = vec![
            projected_receipt(
                "gate:run-planning",
                ReceiptKind::Gate,
                10,
                "started",
                None,
                Some("run:planning"),
                &[("parent_ref", "brief:party")],
            ),
            projected_receipt(
                "outbound:intent:invite-aki",
                ReceiptKind::Outbound,
                11,
                "delivered_to_channel",
                None,
                Some("intent:invite-aki"),
                &[
                    ("run_ref", "run:planning"),
                    ("counterparty_ref", "person:aki"),
                    ("budget_debit", "4"),
                ],
            ),
        ];

        let projection = project_receipts_by_brief("brief:party", receipts);

        assert_eq!(projection.runs.len(), 1);
        assert_eq!(projection.runs[0].run_ref, "run:planning");
        assert_eq!(projection.runs[0].intents.len(), 1);
        assert_eq!(
            projection.runs[0].intents[0].receipts[0]
                .trigger_ref
                .as_deref(),
            Some("intent:invite-aki")
        );
        assert_eq!(projection.budget_debit_total, 4);
    }

    #[test]
    fn brief_projection_chain_walks_nested_runs() {
        let receipts = vec![
            projected_receipt(
                "gate:run-parent",
                ReceiptKind::Gate,
                10,
                "started",
                None,
                Some("run:parent"),
                &[("parent_ref", "brief:party")],
            ),
            projected_receipt(
                "gate:run-child",
                ReceiptKind::Gate,
                11,
                "started",
                None,
                Some("run:child"),
                &[("parent_ref", "run:parent")],
            ),
            projected_receipt(
                "outbound:intent:child",
                ReceiptKind::Outbound,
                12,
                "delivered_to_channel",
                None,
                Some("intent:child"),
                &[
                    ("run_ref", "run:child"),
                    ("intent_ref", "intent:child"),
                    ("budget_debit", "5"),
                ],
            ),
        ];

        let projection = project_receipts_by_brief("brief:party", receipts);
        let child = projection
            .runs
            .iter()
            .find(|run| run.run_ref == "run:child")
            .expect("child run should chain back to brief");

        assert_eq!(child.intents.len(), 1);
        assert_eq!(child.intents[0].intent_ref, "intent:child");
        assert_eq!(child.intents[0].receipts.len(), 1);
        assert_eq!(projection.budget_debit_total, 5);
    }
}
