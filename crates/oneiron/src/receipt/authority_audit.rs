//! OF-224: the dated consent/authority audit, a renderer-neutral projection
//! of the stored AUTHORITY_LOG.
//!
//! One page is one read transaction: the owner proof is revalidated, each
//! row's header and signed body are read, and the fold the rows are judged
//! against is the one in that same snapshot. Nothing is persisted; the log
//! itself stays the only ledger, so no identity or scope text is copied into a
//! second audit store.
//!
//! The page walks the AUTHORITY_LOG type index in entity-id order. Entry ids
//! are content-derived, so that order is neither time order nor causal order,
//! and an entry imported later can sort before a cursor already passed: a
//! reader reloads from the start to see it. Each row carries the clocks it
//! has, each named for what it is: the stored occurred interval and
//! learned-at stamp, and the signer's advisory timestamp the fold never reads.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::kernel::hex_lower;
use crate::Vault;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, FederationLifecycleKind, authority_entry_hash, decode_authority_log_entry_body,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::ports::{EntityRecord, EntityStoreRead};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

/// Rows a page holds when the query names no limit.
pub const AUTHORITY_AUDIT_DEFAULT_LIMIT: usize = 50;
/// The most rows one page holds.
pub const AUTHORITY_AUDIT_MAX_LIMIT: usize = 500;
/// Entries one page examines per row it may hold, so a narrow kind filter
/// over a long log still answers in bounded work and resumes from
/// `next_after`.
pub const AUTHORITY_AUDIT_SCAN_PER_ROW: usize = 16;

/// `vault.authority.audit`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAuditQuery {
    /// Resume after this AUTHORITY_LOG entry ref: the `next_after` of the
    /// page before. `None` starts at the first entry.
    #[serde(default)]
    pub after: Option<EntityId>,
    /// Rows to return, at most [`AUTHORITY_AUDIT_MAX_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
    /// Keep only rows of these kinds; empty keeps every row.
    #[serde(default)]
    pub kinds: BTreeSet<AuthorityAuditEventKind>,
}

/// The display class of one entry. A classification over the op vocabulary,
/// not an authority enum: `source_op` and `detail` keep the exact op.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAuditEventKind {
    /// A capability mint, or a federation connect.
    Grant,
    /// A capability revoke, or a federation disconnect or dissolve.
    Revoke,
    /// A federation confirm (its `detail` keeps accept, rescope, a2a connect
    /// or revoke) or a critical-write confirm (clear or decline).
    Confirm,
    /// Every other op: roster, key, actor-binding, machine, world and
    /// handover maintenance, a capability consume, a federation rescope or
    /// promote. None of these is consent to disclose content.
    Other,
}

/// The order a page's rows follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAuditOrder {
    /// Ascending AUTHORITY_LOG entity id (content-derived): neither time nor
    /// causal order.
    EntryRefAscending,
}

/// One AUTHORITY_LOG entry, projected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAuditRow {
    /// The entry's AUTHORITY_LOG entity id; the page cursor.
    pub entry_ref: EntityId,
    /// BLAKE3 hash of the canonical signed entry (64 hex), the id fold
    /// diagnostics and parent links name.
    pub entry_hash: String,
    pub event_kind: AuthorityAuditEventKind,
    /// The op this row projects, snake_case (`slip_mint`, `federation_confirm`, ...).
    pub source_op: String,
    /// The op's own sub-kind where it has one: a confirm kind, a critical
    /// confirm's disposition, a lifecycle kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Stored occurred interval (Unix seconds), as the writing door stamped it.
    pub occurred_start: u64,
    pub occurred_end: u64,
    /// When this vault's store learned the row (Unix seconds).
    pub learned_at: u64,
    /// The signer's advisory timestamp. The fold never reads it.
    pub advisory_ts: u64,
    /// The primary signer's authority public key (hex). A key, not a person:
    /// actor bindings are separate entries.
    pub signer_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cosigner_keys: Vec<String>,
    /// The signer's sequence number.
    pub seq: u64,
    /// The vault id the entry binds (hex); `None` on genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_ref: Option<String>,
    /// What the op acts on: a slip id, a confirm id, a pact id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// A federation lifecycle op's grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    /// A critical-write confirm's claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    /// A capability mint's holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_ref: Option<String>,
    /// A capability mint's parent slip id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_ref: Option<String>,
    /// A federation op's peer vault id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_vault_ref: Option<String>,
    /// A federation op's consent or pact epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// A capability mint's or a critical confirm's expiry (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Whether the fold of this snapshot holds the entry among its valid
    /// entries. Not "in effect": a valid entry can carry no effect, and a
    /// restrictive fact can stand without its entry being valid.
    pub fold_valid: bool,
    /// The fold's diagnostics that name this entry, snake_case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issue_codes: Vec<String>,
}

/// One page of the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAuditPage {
    pub rows: Vec<AuthorityAuditRow>,
    /// Pass back as `after` for the next page; `None` when this page reached
    /// the end of the log. It is the last entry examined, which a kind
    /// filter may have left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<EntityId>,
    pub order: AuthorityAuditOrder,
    /// Entries this page examined, filtered rows included.
    pub scanned: usize,
}

impl Vault {
    /// The owner's dated AUTHORITY_LOG audit, one page in one read
    /// transaction (OF-224). The owner proof is revalidated in that
    /// transaction, and every row is judged against that snapshot's fold.
    pub fn authority_audit(
        &self,
        owner: &AuthenticatedOwner,
        query: &AuthorityAuditQuery,
    ) -> Result<AuthorityAuditPage> {
        let limit = query
            .limit
            .unwrap_or(AUTHORITY_AUDIT_DEFAULT_LIMIT)
            .clamp(1, AUTHORITY_AUDIT_MAX_LIMIT);
        let scan_cap = limit.saturating_mul(AUTHORITY_AUDIT_SCAN_PER_ROW);
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let issues = FoldIssues::of(&fold);
        let mut rows = Vec::new();
        let mut scanned = 0;
        let mut last = None;
        let mut more = false;
        for id in self
            .store
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_AUTHORITY_LOG, query.after)?
        {
            let id = id?;
            if rows.len() == limit || scanned == scan_cap {
                more = true;
                break;
            }
            scanned += 1;
            last = Some(id);
            let record = self
                .store
                .port_entity_record(&txn, &id)?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            if record.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            if record.body.is_empty() {
                continue;
            }
            let entry = decode_authority_log_entry_body(&record.body)?;
            let row = project_row(id, &record, &entry, &fold, &issues)?;
            if query.kinds.is_empty() || query.kinds.contains(&row.event_kind) {
                rows.push(row);
            }
        }
        Ok(AuthorityAuditPage {
            rows,
            next_after: if more { last } else { None },
            order: AuthorityAuditOrder::EntryRefAscending,
            scanned,
        })
    }
}

/// `vault.authority.audit` on an embedded handle: the vault's embedded
/// owner's audit. A server takes the owner's proof from the request instead.
pub fn authority_audit_embedded(
    memory: &Memory<'_>,
    query: AuthorityAuditQuery,
) -> MemoryResult<AuthorityAuditPage> {
    let owner = memory.embedded_owner("vault.authority.audit")?;
    Ok(memory.vault().authority_audit(&owner, &query)?)
}

/// The fold's diagnostics, indexed by what they name.
struct FoldIssues {
    by_entry: BTreeMap<AuthorityEntryHash, Vec<&'static str>>,
    conflicted_confirms: BTreeSet<[u8; 32]>,
    memory_floor: bool,
}

impl FoldIssues {
    fn of(fold: &AuthorityFold) -> Self {
        let mut issues = Self {
            by_entry: BTreeMap::new(),
            conflicted_confirms: fold.conflicted_critical_write_confirms.clone(),
            memory_floor: false,
        };
        for issue in &fold.issues {
            let (entry, code) = match issue {
                AuthorityFoldIssue::InvalidEntry(entry) => (entry, "invalid_entry"),
                AuthorityFoldIssue::InvalidAncestry(entry) => (entry, "invalid_ancestry"),
                AuthorityFoldIssue::RetiredSigner(entry) => (entry, "retired_signer"),
                AuthorityFoldIssue::UnsettledHandoff(entry) => (entry, "unsettled_handoff"),
                AuthorityFoldIssue::SignerNotInAncestry(entry) => {
                    (entry, "signer_not_in_ancestry")
                }
                AuthorityFoldIssue::NonMonotonicSeq(entry) => (entry, "non_monotonic_seq"),
                AuthorityFoldIssue::StaleRosterApproval(entry) => (entry, "stale_roster_approval"),
                AuthorityFoldIssue::WrongVault(entry) => (entry, "wrong_vault"),
                AuthorityFoldIssue::ConflictingVaultRoot { entry, .. } => {
                    (entry, "conflicting_vault_root")
                }
                AuthorityFoldIssue::MissingAuthorityConsent(entry) => {
                    (entry, "missing_authority_consent")
                }
                AuthorityFoldIssue::MissingQuorum(entry) => (entry, "missing_quorum"),
                AuthorityFoldIssue::FederationLifecycleRejected { entry, .. } => {
                    (entry, "federation_lifecycle_rejected")
                }
                AuthorityFoldIssue::ActorBindingRejected { entry, .. } => {
                    (entry, "actor_binding_rejected")
                }
                AuthorityFoldIssue::CriticalWriteConfirmConflict { confirm_id } => {
                    issues.conflicted_confirms.insert(*confirm_id);
                    continue;
                }
                AuthorityFoldIssue::FoldMemoryFloor { .. } => {
                    issues.memory_floor = true;
                    continue;
                }
            };
            issues.by_entry.entry(*entry).or_default().push(code);
        }
        for entry in &fold.refused_world_edits {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_world_edit");
        }
        for entry in &fold.refused_world_keys {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_world_key");
        }
        issues
    }

    fn codes(&self, hash: &AuthorityEntryHash, op: &AuthorityOp) -> Vec<String> {
        let mut codes: Vec<String> = self
            .by_entry
            .get(hash)
            .into_iter()
            .flatten()
            .map(|code| (*code).to_owned())
            .collect();
        if let AuthorityOp::CriticalWriteConfirm(action) = op
            && self.conflicted_confirms.contains(&action.confirm_id)
        {
            codes.push("critical_write_confirm_conflict".to_owned());
        }
        if self.memory_floor {
            codes.push("fold_memory_floor".to_owned());
        }
        codes
    }
}

fn key_hex(key: &AuthorityKey) -> String {
    match key {
        AuthorityKey::Ed25519(bytes) => hex_lower(bytes),
        AuthorityKey::P256(bytes) => hex_lower(bytes),
    }
}

/// What an op says, in the row's terms.
#[derive(Default)]
struct OpFields {
    detail: Option<String>,
    subject_ref: Option<String>,
    grant_ref: Option<String>,
    claim_ref: Option<String>,
    holder_ref: Option<String>,
    parent_ref: Option<String>,
    peer_vault_ref: Option<String>,
    epoch: Option<u64>,
    expires_at: Option<u64>,
}

/// The class, op name and fields of one op.
fn classify(op: &AuthorityOp) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    use AuthorityAuditEventKind::{Confirm, Grant, Other, Revoke};
    match op {
        AuthorityOp::SlipMint(action) => (
            Grant,
            "slip_mint",
            OpFields {
                subject_ref: Some(hex_lower(&action.claims.slip_id)),
                holder_ref: Some(action.claims.holder_ref.clone()),
                parent_ref: action.claims.parent_id.as_ref().map(|id| hex_lower(id)),
                expires_at: Some(action.claims.expires_at),
                ..OpFields::default()
            },
        ),
        AuthorityOp::SlipRevoke { slip_id } => (
            Revoke,
            "slip_revoke",
            OpFields {
                subject_ref: Some(hex_lower(slip_id)),
                ..OpFields::default()
            },
        ),
        AuthorityOp::SlipConsume { slip_id } => (
            Other,
            "slip_consume",
            OpFields {
                subject_ref: Some(hex_lower(slip_id)),
                ..OpFields::default()
            },
        ),
        AuthorityOp::FederationConfirm(action) => (
            Confirm,
            "federation_confirm",
            OpFields {
                detail: Some(action.kind.as_str().to_owned()),
                subject_ref: Some(hex_lower(&action.confirm_id)),
                peer_vault_ref: Some(hex_lower(&action.peer_vault_id)),
                epoch: Some(action.epoch),
                ..OpFields::default()
            },
        ),
        AuthorityOp::CriticalWriteConfirm(action) => (
            Confirm,
            "critical_write_confirm",
            OpFields {
                detail: Some(action.disposition.as_str().to_owned()),
                subject_ref: Some(hex_lower(&action.confirm_id)),
                claim_ref: Some(action.claim_id.to_hex()),
                expires_at: Some(action.expires_at),
                ..OpFields::default()
            },
        ),
        AuthorityOp::FederationLifecycle(action) => (
            match action.kind {
                FederationLifecycleKind::Connect => Grant,
                FederationLifecycleKind::Disconnect | FederationLifecycleKind::Dissolve => Revoke,
                FederationLifecycleKind::Rescope | FederationLifecycleKind::Promote => Other,
            },
            "federation_lifecycle",
            OpFields {
                detail: Some(action.kind.as_str().to_owned()),
                subject_ref: Some(hex_lower(&action.pact_id)),
                grant_ref: Some(action.grant_ref.to_hex()),
                peer_vault_ref: Some(hex_lower(&action.peer_vault_id)),
                epoch: Some(action.pact_epoch),
                ..OpFields::default()
            },
        ),
        AuthorityOp::Genesis { .. } => (Other, "genesis", OpFields::default()),
        AuthorityOp::EnrollDevice { .. } => (Other, "enroll_device", OpFields::default()),
        AuthorityOp::RevokeDevice { .. } => (Other, "revoke_device", OpFields::default()),
        AuthorityOp::RotateKey { .. } => (Other, "rotate_key", OpFields::default()),
        AuthorityOp::ReRoot { .. } => (Other, "re_root", OpFields::default()),
        AuthorityOp::BindActor { .. } => (Other, "bind_actor", OpFields::default()),
        AuthorityOp::RebindActor { .. } => (Other, "rebind_actor", OpFields::default()),
        AuthorityOp::RevokeActor { .. } => (Other, "revoke_actor", OpFields::default()),
        AuthorityOp::MachineProfile(_) => (Other, "machine_profile", OpFields::default()),
        AuthorityOp::OwnerRoot(_) => (Other, "owner_root", OpFields::default()),
        AuthorityOp::WorldPrivacy(_) => (Other, "world_privacy", OpFields::default()),
        AuthorityOp::WorldKeyWraps(_) => (Other, "world_key_wraps", OpFields::default()),
        AuthorityOp::OwnerHandover(_) => (Other, "owner_handover", OpFields::default()),
    }
}

fn project_row(
    id: EntityId,
    record: &EntityRecord,
    entry: &AuthorityLogEntry,
    fold: &AuthorityFold,
    issues: &FoldIssues,
) -> Result<AuthorityAuditRow> {
    let hash = authority_entry_hash(entry)?;
    let (event_kind, source_op, fields) = classify(&entry.op);
    Ok(AuthorityAuditRow {
        entry_ref: id,
        entry_hash: hex_lower(&hash),
        event_kind,
        source_op: source_op.to_owned(),
        detail: fields.detail,
        occurred_start: record.occurred.start,
        occurred_end: record.occurred.end,
        learned_at: record.learned_at,
        advisory_ts: entry.ts,
        signer_key: key_hex(&entry.signer.public_key),
        cosigner_keys: entry
            .cosigns
            .iter()
            .map(|cosign| key_hex(&cosign.public_key))
            .collect(),
        seq: entry.seq,
        vault_ref: entry.vault_id.as_ref().map(|id| hex_lower(id)),
        subject_ref: fields.subject_ref,
        grant_ref: fields.grant_ref,
        claim_ref: fields.claim_ref,
        holder_ref: fields.holder_ref,
        parent_ref: fields.parent_ref,
        peer_vault_ref: fields.peer_vault_ref,
        epoch: fields.epoch,
        expires_at: fields.expires_at,
        fold_valid: fold.valid_entries.contains(&hash),
        issue_codes: issues.codes(&hash, &entry.op),
    })
}
