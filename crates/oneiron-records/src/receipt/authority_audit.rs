//! Moved from `crates/oneiron/src/receipt/authority_audit.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::receipt::authority_audit::AuthorityAuditEventKind;
pub use oneiron_verb_wire::receipt::authority_audit::AuthorityAuditQuery;
use serde::Deserialize;
use serde::Serialize;

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
    /// The execution receipt named by a signed membership withdrawal or Owner handover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// The grant ids the signed Owner handover says the change affected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_grants: Vec<String>,
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

/// One entry the adopted checkpoint image covers and this vault does not
/// store: a cold, checkpoint-attested row. It holds what the image's row
/// summary holds and nothing more, so it names no clock, op kind or subject.
/// It proves membership under the attested image only: not that the entry is
/// valid or authorizes anything, that a custodian holding its signed bytes is
/// online, that an archive was fetched, or that the covered history was
/// replayed independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdAuthorityAuditRow {
    /// The AUTHORITY_LOG entity id the entry hash derives; the page cursor.
    pub entry_ref: EntityId,
    /// BLAKE3 hash of the canonical signed entry (64 hex).
    pub entry_hash: String,
    /// The adopted image that covers the entry: its id (64 hex), the adopted
    /// pin's checkpoint.
    pub checkpoint: String,
    /// The primary signer's authority public key (hex), as the image's row
    /// summary names it.
    pub signer_key: String,
    /// The signer's sequence number.
    pub seq: u64,
    /// The parent entry hashes (64 hex each), in the signed entry's order.
    pub parents: Vec<String>,
    /// Whether the fold of this snapshot holds the entry among its valid
    /// entries: the current fold's verdict, not the image's, and not "in
    /// effect".
    pub fold_valid: bool,
    /// The fold's diagnostics that name this entry, snake_case, as a stored
    /// row carries them (`held_back` among them, FIX 1104).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issue_codes: Vec<String>,
}

/// One page of the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAuditPage {
    /// The stored entries this page lists, projected.
    pub rows: Vec<AuthorityAuditRow>,
    /// Pass back as `after` for the next page; `None` when this page reached
    /// the end of the log. It is the last entry examined, stored or cold,
    /// which a kind filter may have left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<EntityId>,
    pub order: AuthorityAuditOrder,
    /// Entries this page examined, filtered and cold rows included.
    pub scanned: usize,
    /// The entries the adopted checkpoint image covers that this vault does
    /// not store, in the same id order and cursor as `rows` and counted
    /// toward the same limit. Empty, and omitted, on a vault that adopted no
    /// image.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cold_attested: Vec<ColdAuthorityAuditRow>,
    /// The membership changes this vault executed with no host issuer to
    /// sign them whose carrier-signed record is not in the log yet (FIX
    /// 12335): pending, never signed. Listed on a page with no `after`, in
    /// receipt id order, whatever `kinds` names; empty, and omitted, when
    /// none is pending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_membership_executions: Vec<PendingMembershipExecutionRow>,
    /// The owner's grants and revokes of the audit_read power, oldest first
    /// (Engine RULING AUDITREAD-GRANT-HOME = A), so an auditor sees who else
    /// audits. Listed on a page with no `after`, whatever `kinds` names;
    /// empty, and omitted, when the owner never acted on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_read_acts: Vec<AuditReadActRow>,
}

/// One owner act on the audit_read power: a grant or a revoke his
/// `vault.audit_read.*` verbs recorded. Value-free: ids, the change and a
/// time. It is this install's receipt of the owner's act, not a signed log
/// entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReadActRow {
    /// The act's place in this install's access-grant owner-act index.
    pub sequence: u64,
    /// The owner who acted.
    pub owner: EntityId,
    /// The person or agent the act gave the power to or took it from; none
    /// once that principal was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<EntityId>,
    /// The holder's audit_read grant row.
    pub grant_ref: EntityId,
    /// `grant` or `revoke`.
    pub change: crate::access_grant::owner_act::AccessGrantActChange,
    /// When the act was recorded (Unix seconds, the vault's clock).
    pub at: u64,
}

/// One membership change whose signed record is pending (FIX 12335): what
/// its writer executed, as the intent this vault keeps holds it. Value-free:
/// ids, a cause and a time. It is no log entry and proves nothing signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMembershipExecutionRow {
    /// The change's execution receipt id.
    pub receipt: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    /// The shared act the change executed; an Owner act's alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
    /// The power or act that made the change, snake_case (`remove_member`,
    /// `leave`, `transfer_ownership`, ...).
    pub cause: String,
    /// The PERSON who executed the change (hex).
    pub person: String,
    /// The member whose role moved (hex).
    pub member: String,
    /// When the change was executed (Unix seconds, store clock).
    pub executed_at: u64,
    /// The Grants an owner's signed mint made that the change deleted and
    /// whose signed withdrawal is pending (hex).
    pub withdrawn_grants: Vec<String>,
    /// Whether the change hands the Owner role over, its signed handover
    /// pending with it.
    pub handover: bool,
}
