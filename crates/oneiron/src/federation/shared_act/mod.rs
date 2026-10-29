//! Typed execution of the shared acts the vault preset lists, beside the
//! ordinary membership changes that never wait. The pending-act store keeps
//! the objection window and stays effect-free; this module validates each
//! act's typed plan, claims the matured act in the writer that applies its
//! effect, and records one receipt that every affected holder is told about.
//! Erase keeps its own executor (`Memory::execute_completed_entity_erase`),
//! and once it has erased the record [`Vault::record_erase_completion`]
//! writes the act's receipt and tells the Owners (OF-150); a Member's or
//! Admin's ask for one is `erase_ask`.
mod erase_ask;
mod execute;
mod membership;
mod removal;
mod removal_archive;
mod removal_import;

pub use erase_ask::{
    EraseAskKind, EraseAskStatus, NOTIFICATION_PRODUCER_ERASE_ASK, SharedEraseAsk,
};
pub use membership::{
    OwnerRecoveryAuthorization, SHARED_INVITATION_TTL_SECS, SharedInvitation, SharedInvitationState,
};

use super::FederationGrantRole as Role;
use super::pending_act::{LiveActHolder, check_vault, decode, encode, invalid, key};
use crate::authority::{HostSlipIssuer, OwnerHandover, OwnerHandoverCause};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Named, SideTable};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

use super::PendingAuthorityAct;

const RECEIPT_PREFIX: &[u8] = b"shared-act:receipt:v1:";
const OUTCOME_PREFIX: &[u8] = b"shared-act:outcome:v1:";
/// How long an export-first removal's archive stays retrievable by the
/// removed Owner it was delivered to, from that delivery, on the store clock
/// (FIX 1300: the Engine's ruling on OF-158 names 90 days). A remaining
/// Owner's re-run of the removal delivers it again for a full term.
pub const REMOVAL_EXPORT_RETAIN_SECS: u64 = 90 * 24 * 60 * 60;
const PLAN_VERSION: u8 = 1;
/// How long a deleted vault stays in backups, so disaster recovery can return it.
pub const DELETED_VAULT_BACKUP_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;

/// The executed delete-the-vault act. Key: `()` (singleton).
const SHARED_VAULT_DELETION: SideTable<(), SharedVaultDeletion, LegacyJson> =
    SideTable::new(&side_table::SHARED_VAULT_DELETION);

/// Each export-first removal's archive, bound to the removed Owner, with its
/// records' frozen positions (FIX-LIST 8224). Key: hex32 (removed Owner)
/// ":" hex32 (receipt id).
const REMOVAL_EXPORT: SideTable<String, removal_archive::StoredRemovalExport, Named> =
    SideTable::new(&side_table::SHARED_ACT_REMOVAL_EXPORT);

/// The row key of `member`'s archive from the removal receipt `receipt_id`.
fn removal_export_key(member: &str, receipt_id: &str) -> String {
    format!("{member}:{receipt_id}")
}

/// The acts the shared preset lists. Their names are the policy row names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedActKind {
    DeleteVault,
    Erase,
    TransferOwnership,
    RemoveOwner,
}
impl SharedActKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeleteVault => "delete_vault",
            Self::Erase => "erase",
            Self::TransferOwnership => "transfer_ownership",
            Self::RemoveOwner => "remove_owner",
        }
    }
    pub fn parse(act: &str) -> Option<Self> {
        match act {
            "delete_vault" => Some(Self::DeleteVault),
            "erase" => Some(Self::Erase),
            "transfer_ownership" => Some(Self::TransferOwnership),
            "remove_owner" => Some(Self::RemoveOwner),
            _ => None,
        }
    }
}

/// Payload of a `delete_vault` act. The vault id is the act's own.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteVaultPlan {
    pub v: u8,
}
/// Payload of a `transfer_ownership` act: the starting Owner hands the vault
/// to `to`, then keeps `from_keeps` or leaves when it is `None`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferOwnershipPlan {
    pub v: u8,
    pub from: String,
    pub to: String,
    pub from_keeps: Option<Role>,
}
/// Payload of a `remove_owner` act. `target` keeps `target_keeps` or leaves
/// when it is `None`; removing the last Owner needs a `successor`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveOwnerPlan {
    pub v: u8,
    pub target: String,
    pub successor: Option<String>,
    pub target_keeps: Option<Role>,
    /// The removal flow's "export first?": on yes, the removal runs only
    /// with an export of what the target could read, delivered to them
    /// alone (FIX 1300). Removal alone exports nothing.
    pub export_first: bool,
}

/// What one executed act or membership change did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedVaultChange {
    VaultDeleted {
        backup_retain_until: u64,
    },
    OwnershipTransferred {
        from: String,
        to: String,
        from_keeps: Option<Role>,
    },
    OwnerRemoved {
        target: String,
        successor: Option<String>,
        target_keeps: Option<Role>,
    },
    MemberAdded {
        member: String,
        role: Role,
    },
    /// An `add_member` holder invited `member`; nothing is granted yet.
    MemberInvited {
        invitation: String,
        member: String,
        role: Role,
        expires_at: u64,
    },
    /// `member` accepted the invitation and holds `role` now.
    InvitationAccepted {
        invitation: String,
        member: String,
        role: Role,
    },
    InvitationDeclined {
        invitation: String,
        member: String,
    },
    InvitationWithdrawn {
        invitation: String,
        member: String,
    },
    MemberRoleChanged {
        member: String,
        from: Role,
        to: Role,
    },
    MemberRemoved {
        member: String,
    },
    MemberLeft {
        member: String,
    },
    OwnerRecovered {
        from: String,
        to: String,
    },
    /// A held erase's own executor erased `record` (entity id hex);
    /// `redaction` names its redaction receipt, when one was written.
    RecordErased {
        record: String,
        redaction: Option<String>,
    },
}

/// The durable receipt of one executed shared act or membership change. An
/// act's `ActExecution` names this receipt's id; a membership change that
/// never waited has no act or request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActExecutionReceipt {
    pub id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub act_id: Option<String>,
    pub request_id: Option<String>,
    pub actor: String,
    pub change: SharedVaultChange,
    /// Grant records the change rewrote or deleted.
    pub grants: Vec<String>,
    /// Capability slips revoked with the change, hex.
    pub revoked_slips: Vec<String>,
    /// The export made for a removed Owner before the removal.
    pub export: Option<SharedActExport>,
    /// The hash (hex) of the host-signed `OwnerHandover` AUTHORITY_LOG
    /// entry an ownership change wrote in this writer, which names this
    /// receipt back. `None` when nothing was signed: a membership change, or
    /// an act run with no slip issuer.
    pub authority_entry: Option<String>,
    /// The person who authorized the change, PERSON hex, when the writer
    /// holds one apart from its actor: the attested account owner of a
    /// managed vault's proof-of-control recovery, as its signed handover
    /// names him (FIX 5401). `None` for every other change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizer: Option<String>,
    pub completed_at: u64,
}

/// What an export-first removal exported for `member`: the record count,
/// the BLAKE3 of the archive (OF-222), never its content, and the diaries
/// the export read (OF-490).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActExport {
    pub member: String,
    pub records: u64,
    pub digest: String,
    pub diary_reads: Vec<crate::batch::export::ExportDiaryRead>,
}

/// An executed act's receipt and, for an export-first removal, where its
/// archive went. The archive itself is the removed Owner's alone (FIX 1300):
/// the Owner who ran the act never receives it.
#[derive(Debug, Clone)]
pub struct SharedActExecution {
    pub receipt: SharedActExecutionReceipt,
    pub delivery: Option<RemovalExportDelivery>,
    /// The records this execution's removal export counted, which its
    /// receipt's count and digest derive from (FIX 3412). `None` when this
    /// execution built no export, a re-delivery included: that archive is
    /// the one the first execution built.
    pub export_records: Option<Vec<EntityId>>,
}

/// Where an export-first removal's archive went (FIX 1300): to the removed
/// Owner, bound to them as its one recipient, retrievable by them until
/// `expires_at`. Never the archive's content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalExportDelivery {
    /// The removal's receipt id, which keys the archive.
    pub receipt_id: String,
    /// The removed Owner, PERSON hex.
    pub recipient: String,
    /// BLAKE3 of the archive, lowercase hex, as the receipt records it.
    pub digest: String,
    /// When it was last delivered: the removal, or a remaining Owner's re-run.
    pub delivered_at: u64,
    pub expires_at: u64,
}

/// An export-first removal's archive of what the removed Owner could read,
/// in the whole-vault archive's shape (OF-222), re-importable into a fresh
/// vault. It is delivered to the removed Owner alone and kept for them until
/// `expires_at` (FIX 1300). Their device fetches it with the slip the removal
/// revoked (`Vault::removed_owner_archive`, `Vault::removed_owner_exports`),
/// so a lost answer never loses it; a remaining Owner's re-run of the removal
/// delivers it again for a full term.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalExportCopy {
    pub receipt_id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    /// The removed Owner, PERSON hex: the archive's one recipient.
    pub member: String,
    /// When it was last delivered: the removal, or a remaining Owner's re-run.
    pub delivered_at: u64,
    pub expires_at: u64,
    pub export: crate::memory::MemoryExport,
}

impl RemovalExportCopy {
    /// What the delivery tells an Owner: never the archive.
    fn delivery(&self) -> RemovalExportDelivery {
        RemovalExportDelivery {
            receipt_id: self.receipt_id.clone(),
            recipient: self.member.clone(),
            digest: self.export.digest.clone(),
            delivered_at: self.delivered_at,
            expires_at: self.expires_at,
        }
    }
}

/// One recipient's durable notice that a receipt was written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActOutcome {
    pub receipt_id: String,
    pub act_id: Option<String>,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub recipient: String,
    pub change: SharedVaultChange,
    pub completed_at: u64,
}

/// Domain of a home-signed outcome notice (FIX 2053).
pub const SHARED_ACT_OUTCOME_NOTICE_DOMAIN: &[u8] = b"oneiron/shared-act/outcome-notice/v1";

/// One outcome notice its home signed with its host root key (FIX 2053), so
/// a removed device can act on a deletion it learns from no other source. A
/// receiver verifies `signature` over [`shared_act_outcome_transcript`]
/// against the home root it already trusts, never the key the notice
/// carries, and checks the authority vault id, local vault id and recipient
/// before it discards anything. Its JSON form is hex for every byte field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "SignedOutcomeWire", try_from = "SignedOutcomeWire")]
pub struct SignedSharedActOutcome {
    /// The home's Genesis-rooted authority vault id.
    pub authority_vault_id: crate::authority::AuthorityVaultId,
    pub outcome: SharedActOutcome,
    pub signature: crate::authority::AuthoritySignature,
}

/// The bytes a home signs for `outcome`: the notice domain, then the
/// canonical JSON of the authority vault id (hex) and every outcome field
/// (receipt, act, local vault id, recipient, change with its deadlines,
/// completion time), in declaration order.
pub fn shared_act_outcome_transcript(
    authority_vault_id: &crate::authority::AuthorityVaultId,
    outcome: &SharedActOutcome,
) -> Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct Transcript<'a> {
        authority_vault_id: String,
        outcome: &'a SharedActOutcome,
    }
    let body = crate::authority::canonical(&Transcript {
        authority_vault_id: crate::entity_id::bytes_to_hex_lower(authority_vault_id),
        outcome,
    })?;
    Ok([SHARED_ACT_OUTCOME_NOTICE_DOMAIN, &body].concat())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedOutcomeWire {
    authority_vault_id: String,
    outcome: SharedActOutcome,
    signature: OutcomeSignatureWire,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeSignatureWire {
    suite: String,
    public_key: String,
    signature: String,
}

impl From<SignedSharedActOutcome> for SignedOutcomeWire {
    fn from(signed: SignedSharedActOutcome) -> Self {
        let hex = crate::entity_id::bytes_to_hex_lower;
        let (suite, public_key) = match &signed.signature.public_key {
            crate::authority::AuthorityKey::Ed25519(key) => ("ed25519", hex(key)),
            crate::authority::AuthorityKey::P256(key) => ("p256", hex(key)),
        };
        Self {
            authority_vault_id: hex(&signed.authority_vault_id),
            outcome: signed.outcome,
            signature: OutcomeSignatureWire {
                suite: suite.to_owned(),
                public_key,
                signature: hex(&signed.signature.signature),
            },
        }
    }
}

impl TryFrom<SignedOutcomeWire> for SignedSharedActOutcome {
    type Error = &'static str;

    fn try_from(wire: SignedOutcomeWire) -> std::result::Result<Self, Self::Error> {
        const MALFORMED: &str = "malformed signed outcome notice";
        let unhex = |value: &str| -> Option<Vec<u8>> {
            if !value.len().is_multiple_of(2) || !value.is_ascii() {
                return None;
            }
            value
                .as_bytes()
                .chunks(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .collect()
        };
        let authority_vault_id = unhex(&wire.authority_vault_id)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(MALFORMED)?;
        let key = unhex(&wire.signature.public_key).ok_or(MALFORMED)?;
        let public_key = match wire.signature.suite.as_str() {
            "ed25519" => crate::authority::AuthorityKey::Ed25519(
                <[u8; 32]>::try_from(key).map_err(|_| MALFORMED)?,
            ),
            "p256" => crate::authority::AuthorityKey::P256(key),
            _ => return Err(MALFORMED),
        };
        let signature = crate::authority::AuthoritySignature {
            suite: public_key.suite(),
            public_key,
            signature: unhex(&wire.signature.signature).ok_or(MALFORMED)?,
        };
        signature.validate().map_err(|_| MALFORMED)?;
        Ok(Self {
            authority_vault_id,
            outcome: wire.outcome,
            signature,
        })
    }
}

/// The engine's record that the vault was deleted. Hosts stop serving it and
/// keep its backups until `backup_retain_until`, then let them go.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVaultDeletion {
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub act_id: String,
    pub receipt_id: String,
    pub deleted_at: u64,
    pub backup_retain_until: u64,
}

/// One applied effect, before its receipt is written.
struct Effect {
    change: SharedVaultChange,
    grants: Vec<EntityId>,
    revoked_slips: Vec<[u8; 32]>,
    /// Holders the change concerns beyond the live Owners and the actor.
    notify: BTreeSet<EntityId>,
}

/// Live Owners carrying the act's verb; `None` checks the role alone, before
/// an act has snapshotted its row.
fn live_owners(holders: &[LiveActHolder], verb: Option<&str>) -> BTreeSet<EntityId> {
    holders
        .iter()
        .filter(|holder| match verb {
            Some(verb) => holder.can(&[Role::Owner], verb),
            None => holder.role == Role::Owner,
        })
        .map(|holder| holder.member)
        .collect()
}
fn non_root(role: Option<Role>) -> Result<()> {
    match role {
        None | Some(Role::Admin | Role::Member | Role::Viewer) => Ok(()),
        Some(_) => Err(invalid()),
    }
}
fn hex_id(id: &str) -> Result<EntityId> {
    EntityId::from_hex(id)
}

impl Vault {
    /// Start a `delete_vault` act under the vault's policy row.
    pub fn propose_delete_vault(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<PendingAuthorityAct> {
        let plan = encode(&DeleteVaultPlan { v: PLAN_VERSION })?;
        self.start_authority_act(starter, vault_id, SharedActKind::DeleteVault.as_str(), plan)
    }
    /// Start a `transfer_ownership` act: the starter, a live Owner, hands
    /// ownership to `to`, a live person who is not yet an Owner.
    pub fn propose_transfer_ownership(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        to: EntityId,
        from_keeps: Option<Role>,
    ) -> Result<PendingAuthorityAct> {
        let plan = {
            let txn = self.store.env.read_txn()?;
            let from = starter.revalidate_person_in_txn(self, &txn)?;
            let plan = TransferOwnershipPlan {
                v: PLAN_VERSION,
                from: from.to_hex(),
                to: to.to_hex(),
                from_keeps,
            };
            check_vault(self, &txn, vault_id)?;
            let holders =
                self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
            let owners = live_owners(&holders, None);
            self.check_handover_in_txn(&txn, owners, from, from_keeps, Some(to))?;
            plan
        };
        self.start_authority_act(
            starter,
            vault_id,
            SharedActKind::TransferOwnership.as_str(),
            encode(&plan)?,
        )
    }
    /// Start a `remove_owner` act against `target`, a live Owner. An Owner
    /// removing themselves signs their own removal; removing the last Owner
    /// names a `successor`.
    pub fn propose_remove_owner(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        target: EntityId,
        successor: Option<EntityId>,
        target_keeps: Option<Role>,
        export_first: bool,
    ) -> Result<PendingAuthorityAct> {
        {
            let txn = self.store.env.read_txn()?;
            starter.revalidate_person_in_txn(self, &txn)?;
            check_vault(self, &txn, vault_id)?;
            let holders =
                self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
            let owners = live_owners(&holders, None);
            self.check_handover_in_txn(&txn, owners, target, target_keeps, successor)?;
        }
        let plan = RemoveOwnerPlan {
            v: PLAN_VERSION,
            target: target.to_hex(),
            successor: successor.map(|id| id.to_hex()),
            target_keeps,
            export_first,
        };
        self.start_authority_act(
            starter,
            vault_id,
            SharedActKind::RemoveOwner.as_str(),
            encode(&plan)?,
        )
    }

    /// An Owner hands over: `loser` is a live Owner, `keeps` is a non-root
    /// role, `gainer` is a live person who is not yet an Owner, and the vault
    /// keeps at least one live Owner afterwards.
    fn check_handover_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        mut owners: BTreeSet<EntityId>,
        loser: EntityId,
        keeps: Option<Role>,
        gainer: Option<EntityId>,
    ) -> Result<()> {
        non_root(keeps)?;
        if !owners.remove(&loser) {
            return Err(invalid());
        }
        if let Some(gainer) = gainer {
            if gainer == loser
                || !crate::consent::person_is_live_in_txn(self, txn, &gainer)?
                || !owners.insert(gainer)
            {
                return Err(invalid());
            }
        }
        if owners.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }

    /// The live Owners holding `act`'s verb at `now`, refused unless both
    /// `actor` and the act's starter stand among them.
    fn act_executors_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        act: &PendingAuthorityAct,
        actor: EntityId,
        now: u64,
    ) -> Result<BTreeSet<EntityId>> {
        let holders = self.live_act_holders(txn, act.vault_id, now)?;
        let owners = live_owners(&holders, Some(&act.required_verb));
        if !owners.contains(&actor) || !owners.contains(&hex_id(&act.starter)?) {
            return Err(invalid());
        }
        Ok(owners)
    }

    /// A re-run of the executed export-first removal `act` by `actor`, who
    /// must stand as a live Owner holding the act's verb (FIX 1300): the
    /// archive kept for `member` under `receipt_id` is delivered to them again,
    /// retrievable for a full term from now. `None` once it has been purged
    /// past its term: it is not rebuilt, as the vault now holds what the
    /// removed Owner never could read.
    fn redeliver_removal_export_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: &PendingAuthorityAct,
        actor: EntityId,
        member: &str,
        receipt_id: &str,
    ) -> Result<Option<RemovalExportDelivery>> {
        check_vault(self, txn, act.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let holders = self.live_act_holders(txn, act.vault_id, now)?;
        if !live_owners(&holders, Some(&act.required_verb)).contains(&actor) {
            return Err(invalid());
        }
        let row_key = removal_export_key(member, receipt_id);
        let Some(mut stored) = REMOVAL_EXPORT.get(&self.store, txn, &row_key)? else {
            return Ok(None);
        };
        stored.copy.delivered_at = now;
        stored.copy.expires_at = now
            .checked_add(REMOVAL_EXPORT_RETAIN_SECS)
            .ok_or_else(invalid)?;
        REMOVAL_EXPORT.put(&self.store, txn, &row_key, &stored)?;
        Ok(Some(stored.copy.delivery()))
    }

    /// Persist the receipt and one notice to each live Owner, the actor and
    /// every holder the change concerns, in the change's own writer.
    #[allow(clippy::too_many_arguments)]
    fn record_shared_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: String,
        vault_id: u64,
        act: Option<(String, String)>,
        actor: EntityId,
        owners: BTreeSet<EntityId>,
        effect: Effect,
        export: Option<SharedActExport>,
        authority_entry: Option<crate::authority::AuthorityEntryHash>,
        authorizer: Option<EntityId>,
        now: u64,
    ) -> Result<SharedActExecutionReceipt> {
        let (act_id, request_id) = act.unzip();
        let receipt = SharedActExecutionReceipt {
            id,
            vault_id,
            act_id,
            request_id,
            actor: actor.to_hex(),
            change: effect.change,
            grants: effect.grants.iter().map(EntityId::to_hex).collect(),
            revoked_slips: effect
                .revoked_slips
                .iter()
                .map(|slip| crate::entity_id::bytes_to_hex_lower(slip))
                .collect(),
            export,
            authority_entry: authority_entry
                .as_ref()
                .map(|hash| crate::entity_id::bytes_to_hex_lower(hash)),
            authorizer: authorizer.as_ref().map(EntityId::to_hex),
            completed_at: now,
        };
        self.store
            .vault_meta
            .put(txn, &key(RECEIPT_PREFIX, &receipt.id), &encode(&receipt)?)?;
        let mut recipients = owners;
        recipients.insert(actor);
        recipients.extend(effect.notify);
        for recipient in recipients {
            let outcome = SharedActOutcome {
                receipt_id: receipt.id.clone(),
                act_id: receipt.act_id.clone(),
                vault_id,
                recipient: recipient.to_hex(),
                change: receipt.change.clone(),
                completed_at: now,
            };
            let outcome_key = key(
                OUTCOME_PREFIX,
                &format!("{}:{}", recipient.to_hex(), receipt.id),
            );
            self.store
                .vault_meta
                .put(txn, &outcome_key, &encode(&outcome)?)?;
        }
        Ok(receipt)
    }

    fn shared_act_receipt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &str,
    ) -> Result<Option<SharedActExecutionReceipt>> {
        let id = EntityId::from_hex(id)?;
        self.store
            .vault_meta
            .get(txn, &key(RECEIPT_PREFIX, &id.to_hex()))?
            .map(|raw| decode(&raw))
            .transpose()
    }
    /// Whether `reader` holds a notice of the receipt `receipt_id`. The one
    /// rule for who reads a receipt back, here or by re-running its act.
    fn reader_was_told_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: EntityId,
        receipt_id: &str,
    ) -> Result<bool> {
        let notice = key(OUTCOME_PREFIX, &format!("{}:{receipt_id}", reader.to_hex()));
        Ok(self.store.vault_meta.get(txn, &notice)?.is_some())
    }
}

/// [`Vault::shared_vault_deletion_in_txn`] for a reader that holds a `Store`
/// and no `Vault` (FIX 7461): the same row.
pub(crate) fn shared_vault_deletion_for_store_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<SharedVaultDeletion>> {
    SHARED_VAULT_DELETION.get(store, txn, &())
}
