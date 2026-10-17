//! Typed execution of the shared acts the vault preset lists, beside the
//! ordinary membership changes that never wait. The pending-act store keeps
//! the objection window and stays effect-free; this module validates each
//! act's typed plan, claims the matured act in the writer that applies its
//! effect, and records one receipt that every affected holder is told about.
//! Erase keeps its own executor (`Memory::execute_completed_entity_erase`).
mod membership;

use super::FederationGrantRole as Role;
use super::pending_act::{LiveActHolder, check_vault, decode, encode, invalid, key};
use crate::authority::{HostSlipIssuer, OwnerHandover, OwnerHandoverCause};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

use super::PendingAuthorityAct;

const RECEIPT_PREFIX: &[u8] = b"shared-act:receipt:v1:";
const OUTCOME_PREFIX: &[u8] = b"shared-act:outcome:v1:";
const PLAN_VERSION: u8 = 1;
/// How long a deleted vault stays in backups, so disaster recovery can return it.
pub const DELETED_VAULT_BACKUP_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;

/// The executed delete-the-vault act. Key: `()` (singleton).
const SHARED_VAULT_DELETION: SideTable<(), SharedVaultDeletion, LegacyJson> =
    SideTable::new(&side_table::SHARED_VAULT_DELETION);

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
    /// with an export of what the target could read, handed to the host
    /// for them. Removal alone exports nothing.
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
}

/// The durable receipt of one executed shared act or membership change. An
/// act's `ActExecution` names this receipt's id; a membership change that
/// never waited has no act or request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActExecutionReceipt {
    pub id: String,
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

/// An executed act's receipt, and for an export-first removal the archive
/// of what the removed Owner could read, which the host delivers to them:
/// the whole-vault archive's shape (OF-222), re-importable into a fresh vault.
#[derive(Debug, Clone)]
pub struct SharedActExecution {
    pub receipt: SharedActExecutionReceipt,
    pub export: Option<crate::batch::export::WholeVaultExport>,
}

/// One recipient's durable notice that a receipt was written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActOutcome {
    pub receipt_id: String,
    pub act_id: Option<String>,
    pub vault_id: u64,
    pub recipient: String,
    pub change: SharedVaultChange,
    pub completed_at: u64,
}

/// The engine's record that the vault was deleted. Hosts stop serving it and
/// keep its backups until `backup_retain_until`, then let them go.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVaultDeletion {
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

    /// Execute a completed `delete_vault`, `transfer_ownership` or
    /// `remove_owner` act. Any live Owner may run it once its window has
    /// passed on the store clock with no live objection, while its starter
    /// is still a live Owner. The claim, the effect, the receipt and every
    /// recipient's notice commit in one writer, so the act takes effect at
    /// most once; running it again returns the same receipt. With `slips`,
    /// the capability slips of anyone who lost a role are revoked with it,
    /// and the host signs an ownership change into the authority log as an
    /// `OwnerHandover` naming the act and its receipt.
    /// An export-first removal exports what its target could read before
    /// the writer opens, and records that export's digest in the receipt.
    pub fn execute_completed_shared_act(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedActExecution> {
        let mut export = self
            .removal_export(act_id)?
            .map(|(member, records)| {
                let ids = records.iter().map(|record| record.id).collect();
                // Its diary reads are the removed owner's, who receives it.
                let reader = crate::write_envelope::WriteActor::new(
                    member,
                    crate::edge::EdgeActorClass::Human,
                );
                self.export_records_archive(&ids, reader)
                    .map(|archive| (member, records.len() as u64, archive))
            })
            .transpose()?;
        let mut txn = self.store.env.write_txn()?;
        let actor = executor.revalidate_person_in_txn(self, &txn)?;
        let act = self
            .pending_authority_act_in_txn(&txn, act_id)?
            .ok_or_else(invalid)?;
        let kind = SharedActKind::parse(&act.act).ok_or_else(invalid)?;
        if kind == SharedActKind::Erase {
            // A held erase runs through its own door, which binds the record.
            return Err(invalid());
        }
        if let Some(execution) = &act.execution {
            let receipt = execution
                .receipt
                .as_deref()
                .map(|id| self.shared_act_receipt_in_txn(&txn, id))
                .transpose()?
                .flatten();
            return receipt
                .map(|receipt| SharedActExecution {
                    receipt,
                    export: None,
                })
                .ok_or(Error::ConcurrentWrite("authority act already executed"));
        }
        let creation = check_vault(self, &txn, act.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, act.vault_id, now)?;
        let owners = live_owners(&holders, Some(&act.required_verb));
        if !owners.contains(&actor) || !owners.contains(&hex_id(&act.starter)?) {
            return Err(invalid());
        }
        let receipt_id = self.store.clock.entity_id()?.to_hex();
        let request_id = self.store.clock.entity_id()?.to_hex();
        self.claim_completed_authority_act_in_txn(
            &mut txn,
            &act.id,
            request_id.clone(),
            Some(receipt_id.clone()),
        )?;
        let effect = match kind {
            SharedActKind::DeleteVault => {
                let plan: DeleteVaultPlan = decode(&act.payload)?;
                if plan.v != PLAN_VERSION {
                    return Err(invalid());
                }
                let deletion = SharedVaultDeletion {
                    vault_id: creation.vault_id,
                    act_id: act.id.clone(),
                    receipt_id: receipt_id.clone(),
                    deleted_at: now,
                    backup_retain_until: now
                        .checked_add(DELETED_VAULT_BACKUP_RETENTION_SECS)
                        .ok_or_else(invalid)?,
                };
                SHARED_VAULT_DELETION.put(&self.store, &mut txn, &(), &deletion)?;
                Effect {
                    change: SharedVaultChange::VaultDeleted {
                        backup_retain_until: deletion.backup_retain_until,
                    },
                    grants: Vec::new(),
                    revoked_slips: Vec::new(),
                    notify: BTreeSet::new(),
                }
            }
            SharedActKind::TransferOwnership => {
                let plan: TransferOwnershipPlan = decode(&act.payload)?;
                let (from, to) = (hex_id(&plan.from)?, hex_id(&plan.to)?);
                if plan.v != PLAN_VERSION || plan.from != act.starter {
                    return Err(invalid());
                }
                let (grants, revoked_slips) = self.hand_over_in_txn(
                    &mut txn,
                    act.vault_id,
                    &owners,
                    from,
                    plan.from_keeps,
                    Some(to),
                    slips,
                    now,
                )?;
                Effect {
                    change: SharedVaultChange::OwnershipTransferred {
                        from: plan.from,
                        to: plan.to,
                        from_keeps: plan.from_keeps,
                    },
                    grants,
                    revoked_slips,
                    notify: BTreeSet::from([from, to]),
                }
            }
            SharedActKind::RemoveOwner => {
                let plan: RemoveOwnerPlan = decode(&act.payload)?;
                let target = hex_id(&plan.target)?;
                let successor = plan.successor.as_deref().map(hex_id).transpose()?;
                if plan.v != PLAN_VERSION
                    || plan.export_first != export.as_ref().is_some_and(|(of, ..)| *of == target)
                {
                    return Err(invalid());
                }
                let (grants, revoked_slips) = self.hand_over_in_txn(
                    &mut txn,
                    act.vault_id,
                    &owners,
                    target,
                    plan.target_keeps,
                    successor,
                    slips,
                    now,
                )?;
                Effect {
                    change: SharedVaultChange::OwnerRemoved {
                        target: plan.target,
                        successor: plan.successor,
                        target_keeps: plan.target_keeps,
                    },
                    grants,
                    revoked_slips,
                    notify: BTreeSet::from_iter([Some(target), successor].into_iter().flatten()),
                }
            }
            SharedActKind::Erase => return Err(invalid()),
        };
        let mut authority_entry = None;
        if let Some(issuer) = slips {
            let handover = match &effect.change {
                SharedVaultChange::OwnershipTransferred {
                    from,
                    to,
                    from_keeps,
                } => Some((OwnerHandoverCause::Transfer, from, Some(to), from_keeps)),
                SharedVaultChange::OwnerRemoved {
                    target,
                    successor,
                    target_keeps,
                } => Some((
                    OwnerHandoverCause::Removal,
                    target,
                    successor.as_ref(),
                    target_keeps,
                )),
                _ => None,
            };
            if let Some((cause, from, to, keeps)) = handover {
                authority_entry = Some(self.append_owner_handover_in_txn(
                    &mut txn,
                    issuer,
                    OwnerHandover {
                        shared_vault: act.vault_id,
                        cause,
                        from: hex_id(from)?,
                        to: to.map(|to| hex_id(to)).transpose()?,
                        from_keeps: keeps.map(|role| role.as_str().to_owned()),
                        act: Some(act.id.clone()),
                        proof: None,
                        receipt: receipt_id.clone(),
                    },
                )?);
            }
        }
        let export = export.take().map(|(member, records, archive)| {
            let summary = SharedActExport {
                member: member.to_hex(),
                records,
                digest: blake3::hash(archive.bytes()).to_hex().to_string(),
                diary_reads: archive.diary_reads().to_vec(),
            };
            (summary, archive)
        });
        let (summary, archive) = export.unzip();
        let receipt = self.record_shared_change_in_txn(
            &mut txn,
            receipt_id,
            act.vault_id,
            Some((act.id.clone(), request_id)),
            actor,
            owners,
            effect,
            summary,
            authority_entry,
            now,
        )?;
        txn.commit()?;
        Ok(SharedActExecution {
            receipt,
            export: archive,
        })
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
    /// A receipt its reader was told about: every live Owner at the time,
    /// the actor and each holder the change concerned. Anyone else is refused.
    pub fn shared_act_receipt(
        &self,
        reader: &AuthenticatedOwner,
        receipt_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        let txn = self.store.env.read_txn()?;
        // Person tier: a holder reads the receipts they were told about.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        let receipt_id = EntityId::from_hex(receipt_id)?.to_hex();
        let notice = key(OUTCOME_PREFIX, &format!("{}:{receipt_id}", reader.to_hex()));
        if self.store.vault_meta.get(&txn, &notice)?.is_none() {
            return Err(invalid());
        }
        self.shared_act_receipt_in_txn(&txn, &receipt_id)?
            .ok_or_else(invalid)
    }
    /// The reader's own outcome notices for `vault_id`. A holder a change
    /// removed still reads the notice of that change.
    pub fn shared_act_outcomes(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedActOutcome>> {
        let txn = self.store.env.read_txn()?;
        // Person tier: a holder reads only their own prefix.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        let prefix = key(OUTCOME_PREFIX, &format!("{}:", reader.to_hex()));
        let mut outcomes = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (_, bytes) = entry?;
            let outcome: SharedActOutcome = decode(&bytes)?;
            if outcome.vault_id == vault_id {
                outcomes.push(outcome);
            }
        }
        Ok(outcomes)
    }

    pub(crate) fn shared_vault_deletion_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<SharedVaultDeletion>> {
        SHARED_VAULT_DELETION.get(&self.store, txn, &())
    }
    /// The executed delete-the-vault act, if any. A host stops serving the
    /// vault once this is present and keeps backups only until its deadline.
    pub fn shared_vault_deletion(&self) -> Result<Option<SharedVaultDeletion>> {
        let txn = self.store.env.read_txn()?;
        self.shared_vault_deletion_in_txn(&txn)
    }
}
