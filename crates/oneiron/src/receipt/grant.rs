use crate::ports::EntityStoreRead;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::kernel::{
    FIELD_BRIEF_REF, FIELD_GRANT_REF, FIELD_PERSONA_COMPILE_STAMP, ReceiptKind, ReceiptQuery,
    ReceiptRecord, hex_lower, projection_scan_query,
};
use super::projection::{GrantReceiptProjection, project_receipts_by_grant_limited};
use crate::Vault;
use crate::access_grant::{AccessGrant, AccessGrantScope, decode_live_access_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, standing_outbound_grants_in_txn,
};
use crate::persona_snapshot::{PersonaSnapshotExportRecord, decode_persona_snapshot_export_body};
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
};

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

/// One standing outbound-grant row for the grants page: its standing consent
/// Grant row, by the registry's reference, and the grant id its capability
/// keys and page dispatch name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantLensRow {
    pub grant_ref: String,
    pub grant_id: String,
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

/// Host-interpreted one-tap revoke command for a grants lens row: the
/// consent registry's revoke door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantRevokeAction {
    pub command: String,
    pub grant_ref: String,
}

pub(super) fn standing_outbound_grants_lens(
    vault: &Vault,
    query: StandingOutboundGrantsLensQuery,
) -> Result<StandingOutboundGrantsLens> {
    if query.limit == 0 {
        return Ok(StandingOutboundGrantsLens { grants: Vec::new() });
    }

    let receipt_records = if query.receipt_limit_per_grant == 0 {
        Vec::new()
    } else {
        vault.receipts(projection_scan_query(
            ReceiptQuery::new(query.receipt_limit_per_grant)
                .with_kind(ReceiptKind::Gate)
                .with_kind(ReceiptKind::ScopedRead),
        ))?
    };

    let (policy_floor, grants) = {
        let rtxn = vault.store.env.read_txn()?;
        (
            crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?,
            standing_outbound_grants_in_txn(&vault.store, &rtxn)?,
        )
    };
    let mut rows = Vec::with_capacity(grants.len());
    for grant in &grants {
        let history = OutboundGrantHistory::read(vault, grant)?;
        rows.push(standing_outbound_grant_lens_row(
            grant,
            &history,
            &policy_floor,
            &receipt_records,
            query.receipt_limit_per_grant,
        ));
    }
    rows.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.grant_ref.cmp(&right.grant_ref))
    });
    rows.truncate(query.limit);
    Ok(StandingOutboundGrantsLens { grants: rows })
}

/// What a standing outbound grant's consent receipts say about it: when it
/// was last used and when it was revoked, read from its Used and Revoked
/// receipts, since its row keeps neither.
struct OutboundGrantHistory {
    last_used_at: Option<u64>,
    revoked_at: Option<u64>,
}

impl OutboundGrantHistory {
    fn read(vault: &Vault, grant: &StandingOutboundGrant) -> Result<Self> {
        // Newest first: the first of each reason is the latest.
        let records = vault
            .store
            .gate_decisions_for_grant_ref(&grant.grant_ref())?;
        let latest = |reason: &str| {
            records
                .iter()
                .find(|record| record.reason_codes.iter().any(|code| code == reason))
                .map(|record| record.created_at)
        };
        Ok(Self {
            last_used_at: latest(crate::consent::CONSENT_REASON_STANDING_USED),
            revoked_at: if grant.is_active() {
                None
            } else {
                latest(crate::consent::CONSENT_REASON_REVOKED)
            },
        })
    }
}

fn standing_outbound_grant_lens_row(
    grant: &StandingOutboundGrant,
    history: &OutboundGrantHistory,
    policy_floor: &[u8; 32],
    receipt_records: &[ReceiptRecord],
    receipt_limit: usize,
) -> StandingOutboundGrantLensRow {
    let grant_ref = grant.grant_ref();
    let stale = grant.is_active() && !grant.is_active_under_policy(policy_floor);
    StandingOutboundGrantLensRow {
        grant_ref: grant_ref.clone(),
        grant_id: grant.id.to_hex(),
        scope_dial: grant.scope.dial_label().to_owned(),
        status: grant.status.as_str().to_owned(),
        stale,
        created_at: grant.created_at,
        last_used_at: history.last_used_at,
        revoked_at: history.revoked_at,
        receipt_join: project_receipts_by_grant_limited(
            grant_ref.clone(),
            receipt_records.iter().cloned(),
            receipt_limit,
        ),
        revoke_action: StandingOutboundGrantRevokeAction {
            command: crate::consent::CONSENT_REVOKE_COMMAND.to_owned(),
            grant_ref,
        },
    }
}

pub(super) fn access_grant_receipts(
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
            let Some(grant) = decode_live_access_grant_body(body)? else {
                return Ok(());
            };
            // A vault-wide receipt would disclose an Empty-scope diary pair.
            // This exact-pair grant has no general receipt projection.
            if matches!(
                grant.scope,
                AccessGrantScope::SharedBrief { .. } | AccessGrantScope::DiaryCoreference { .. }
            ) {
                return Ok(());
            }
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
    append_access_grant_scope_fields(&mut fields, &grant.scope);
    // A grant the engine issued on the owner's standing policy names why
    // (FIX 10895).
    if let Some(reason) = crate::ingest::connector_witness_read_reason(&id, grant) {
        fields.insert("reason".to_owned(), reason.to_owned());
    }

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

/// Each standing outbound grant's ScopedRead receipts: its creation and,
/// once revoked, its revocation, at the times its consent Approved and
/// Revoked receipts record. It reads its own snapshots, so it runs outside
/// any read transaction the caller holds.
pub(super) fn outbound_grant_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let grants = {
        let rtxn = vault.store.env.read_txn()?;
        standing_outbound_grants_in_txn(&vault.store, &rtxn)?
    };
    let mut receipts = Vec::new();
    for grant in &grants {
        let history = OutboundGrantHistory::read(vault, grant)?;
        let created =
            outbound_grant_receipt(grant, &history, grant.created_at, "active", "created");
        if query.matches(&created) {
            receipts.push(created);
        }
        if let Some(revoked_at) = history.revoked_at {
            let revoked = outbound_grant_receipt(grant, &history, revoked_at, "revoked", "revoked");
            if query.matches(&revoked) {
                receipts.push(revoked);
            }
        }
    }
    Ok(receipts)
}

fn outbound_grant_receipt(
    grant: &StandingOutboundGrant,
    history: &OutboundGrantHistory,
    occurred_at: u64,
    outcome: &str,
    event_name: &str,
) -> ReceiptRecord {
    let grant_ref = grant.grant_ref();
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_GRANT_REF.to_owned(), grant_ref.clone());
    fields.insert("grant_id".to_owned(), grant.id.to_hex());
    fields.insert("status".to_owned(), grant.status.as_str().to_owned());
    fields.insert("scope_dial".to_owned(), grant.scope.dial_label().to_owned());
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&grant.policy_frontier),
    );
    if let Some(last_used_at) = history.last_used_at {
        fields.insert("last_used_at".to_owned(), last_used_at.to_string());
    }
    append_outbound_grant_scope_fields(&mut fields, &grant.scope);

    ReceiptRecord {
        receipt_id: format!("scoped_read:grant:{grant_ref}:{event_name}"),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at,
        actor: Some(grant.principal_ref.clone()),
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: outbound_grant_job_ref(&grant.scope),
        trigger_ref: Some(format!("grant:{grant_ref}")),
        policy_trace: Vec::new(),
        fields,
    }
}

pub(super) fn federation_share_receipts(
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

pub(super) fn persona_snapshot_export_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
        "persona snapshot export type index",
        |id, _header, body| {
            let record = decode_persona_snapshot_export_body(body)?;
            let receipt = persona_snapshot_export_receipt(id, &record);
            if query.matches(&receipt) {
                receipts.push(receipt);
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn persona_snapshot_export_receipt(
    id: EntityId,
    record: &PersonaSnapshotExportRecord,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        FIELD_PERSONA_COMPILE_STAMP.to_owned(),
        record.compile_stamp_identity(),
    );
    fields.insert("subject_ref".to_owned(), record.subject_ref.to_hex());
    if let Some(audience_ref) = record.audience_ref.as_deref() {
        fields.insert("audience_ref".to_owned(), audience_ref.to_owned());
    }
    fields.insert(
        "compiled_at_secs".to_owned(),
        record.compiled_at_secs.to_string(),
    );
    fields.insert(
        "stale_after_secs".to_owned(),
        record.stale_after_secs.to_string(),
    );
    fields.insert(
        "included_rows".to_owned(),
        record.included_row_ids.len().to_string(),
    );
    fields.insert(
        "struck_rows".to_owned(),
        record.struck_row_ids.len().to_string(),
    );
    fields.insert(
        "takes_included".to_owned(),
        record.takes_included.to_string(),
    );
    fields.insert(
        "artifact_fingerprint".to_owned(),
        record.artifact_fingerprint.clone(),
    );
    // An Omit copy names the vault ref slots both renders left out (FIX
    // 1199); a copy that carries its refs names none, as the record
    // stores none.
    if !record.omitted_refs.is_empty() {
        fields.insert("omitted_refs".to_owned(), record.omitted_refs.join(","));
    }

    ReceiptRecord {
        receipt_id: format!("share:persona_snapshot:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at: record.exported_at_secs,
        actor: Some(record.granted_by.clone()),
        on_behalf_of: None,
        outcome: "exported".to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("persona_snapshot_export:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

/// Hands `visit` every row of `entity_type` in the type index, read to its
/// end: past its threshold row the walk raises one check and reads on (rule
/// 5, FIX 3582).
pub(super) fn scan_entities_by_type(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity_type: u8,
    context: &'static str,
    mut visit: impl FnMut(EntityId, EntityMetadataHeader, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::TypeIndexRows,
        &[entity_type],
    )?;
    for entry in vault
        .store
        .port_entity_ids_by_type(txn, entity_type, None)?
    {
        count.row();
        let id = entry?;
        let Some(raw) = vault
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
        else {
            return Err(Error::CorruptedIndex(context));
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex(context))?;
        if header.entity_type != entity_type {
            return Err(Error::CorruptedIndex(context));
        }
        visit(id, header, &raw[ENTITY_METADATA_HEADER_LEN..])?;
    }
    count.finish(vault);
    Ok(())
}

fn append_access_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: &AccessGrantScope,
) {
    match scope {
        AccessGrantScope::Messages { space_ref }
        | AccessGrantScope::Summaries { space_ref }
        | AccessGrantScope::RelationshipClaims { space_ref } => {
            fields.insert("scope".into(), scope.required_capability().as_str().into());
            fields.insert("space_ref".into(), space_ref.to_hex());
        }
        AccessGrantScope::ConversationMessages { conversation_ref } => {
            fields.insert("scope".to_owned(), "conversation_messages".to_owned());
            fields.insert("conversation_ref".to_owned(), conversation_ref.to_hex());
        }
        AccessGrantScope::ChannelIdentity {
            identity_ref,
            envelope_ref,
        } => {
            fields.insert("scope".to_owned(), "channel_identity".to_owned());
            fields.insert("identity_ref".to_owned(), identity_ref.to_hex());
            fields.insert("envelope_ref".to_owned(), envelope_ref.to_hex());
        }
        AccessGrantScope::SharedBrief { .. } => {
            unreachable!("brief shares have their own Share receipt projection")
        }
        AccessGrantScope::CompanionProfile {
            person_ref,
            facet_ref,
        } => {
            fields.insert("scope".to_owned(), "companion_profile".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
            if let Some(facet_ref) = facet_ref {
                fields.insert("facet_ref".to_owned(), facet_ref.to_hex());
            }
        }
        AccessGrantScope::Calendar { calendar_ref, rung } => {
            fields.insert("scope".to_owned(), "calendar".to_owned());
            fields.insert("calendar_ref".to_owned(), calendar_ref.to_hex());
            fields.insert("rung".to_owned(), rung.as_str().to_owned());
        }
        AccessGrantScope::DiaryCoreference { .. } => {
            unreachable!("private diary grants have no vault-wide receipt projection")
        }
    }
}

fn append_outbound_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: &StandingOutboundGrantScope,
) {
    match scope {
        StandingOutboundGrantScope::ArtifactPublish { artifact } => {
            fields.insert("scope".to_owned(), "artifact_publish".to_owned());
            fields.insert("artifact".to_owned(), artifact.clone());
        }
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
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            tool_data_classes,
            endpoint_allowlist,
        } => {
            fields.insert("scope".to_owned(), "scoped_mcp".to_owned());
            fields.insert("server".to_owned(), server.clone());
            fields.insert("tool".to_owned(), tool.clone());
            fields.insert(
                "data_class_ceiling".to_owned(),
                data_class_ceiling.as_str().to_owned(),
            );
            fields.insert(
                "tool_data_classes".to_owned(),
                tool_data_classes
                    .iter()
                    .map(|class| class.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            fields.insert(
                "endpoint_allowlist".to_owned(),
                endpoint_allowlist.join("\n"),
            );
        }
        StandingOutboundGrantScope::BookingPageInvites { page_ref } => {
            // Token parity with the dial's label: the audit surface and the
            // grants lens spell the scope the same way, and the field name is
            // the scope payload's own field name.
            fields.insert("scope".to_owned(), "booking_page_invites".to_owned());
            fields.insert("page_ref".to_owned(), page_ref.to_hex());
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
        FederationGrantScope::Ask { ask_ref } => {
            fields.insert("scope".to_owned(), "ask".to_owned());
            fields.insert("ask_ref".to_owned(), ask_ref.to_hex());
        }
        FederationGrantScope::Connect { peer_vault_id } => {
            fields.insert("scope".to_owned(), "connect".to_owned());
            fields.insert(
                "peer_vault_id".to_owned(),
                crate::entity_id::bytes_to_hex_lower(&peer_vault_id),
            );
        }
    }
}
