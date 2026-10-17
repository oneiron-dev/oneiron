//! Owner erase that can also take every record in this vault holding the same bytes. The
//! default drops one record and its own hold on shared bytes; the same-bytes flag is a live
//! vault owner's act by hand. A record another owner wrote waits out the shared vault's
//! `erase` veto window first. A GDPR request erases what no legal hold names and keeps the
//! held part, its reason logged (OF-470 C5).

use std::collections::BTreeMap;

use super::support::verify_deletion_authority_in_txn;
use super::{
    DeleteReceipt, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult, SafeDeleteReason,
};
use crate::consent::AuthenticatedOwner;
use crate::deletion::{DeleteEntityPreview, LegalHoldActorKind, LegalHoldTarget};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::federation::{ActExecution, PendingAuthorityAct, SharedVaultPreset};
use crate::store::legal_hold::{self, HoldActor};
use crate::write_envelope::WriteActor;

/// The shared vault's act a held record waits on.
const ERASE_ACT: &str = "erase";

/// The named reason of an owner erase. Both purge the record and write a receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EraseReason {
    #[default]
    UserHardDelete,
    /// A GDPR Art. 17 request: every record holding the same bytes is erased at once, another
    /// owner's included.
    GdprDelete,
}

impl EraseReason {
    const fn safe_delete_reason(self) -> SafeDeleteReason {
        match self {
            Self::UserHardDelete => SafeDeleteReason::UserHardDelete,
            Self::GdprDelete => SafeDeleteReason::GdprDelete,
        }
    }
}

/// What a confirmed erase covers. The same-bytes flag is off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EraseOptions<'p> {
    pub reason: EraseReason,
    /// Also erase every other record in this vault holding the same blob bytes.
    pub also_same_bytes: bool,
    /// The caller's own owner proof. With it, each record held for another
    /// owner starts the shared vault's `erase` act, whose veto window that
    /// vault's owners can object in; without it a held record starts nothing.
    pub veto_starter: Option<&'p AuthenticatedOwner>,
}

/// Why a record holding the same bytes was left in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SameBytesHold {
    /// A shared vault's record whose writer is not the caller, or does not resolve: it needs
    /// that owner's veto window.
    AnotherOwnersRecord,
    /// A legal hold names it. A GDPR request keeps it and erases the rest; its refusal and
    /// reason are in that hold's log, and where Oneiron hosts the bytes it is use-limited
    /// (OF-470 C5, C6).
    LegalHold,
    /// Its erase is deferred, completion pending. Nothing more is said (OF-470 C2).
    CompletionPending,
}

/// What became of one other record holding the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameBytesOutcome {
    Erased(DeleteReceipt),
    /// Left in place. `act_id` names the `erase` act it started, which
    /// [`Memory::execute_completed_entity_erase`] carries out once completed.
    Held {
        reason: SameBytesHold,
        act_id: Option<String>,
    },
    /// Its own checked delete returned this error, for one when it no longer holds the previewed
    /// bytes. As with a confirmed delete that fails part way, it may be unchanged, or its delete
    /// may be accepted and pending (it then reads as deleted and the deletion recovery finishes
    /// it): preview it again to see which.
    Failed(MemoryError),
}

/// The confirmed record's receipt, then one row per other record holding its bytes, in id
/// order. Empty rows without the same-bytes flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityEraseOutcome {
    /// When a GDPR request keeps the confirmed record under a legal hold, it is not erased:
    /// `reason` is the [`SameBytesHold`] code (`privacy_erase_kept` or `completion_pending`)
    /// and `receipt_ref` is `None`.
    pub first: DeleteReceipt,
    pub same_bytes: Vec<(EntityId, SameBytesOutcome)>,
}

impl Memory<'_> {
    /// Erases the previewed record under a named hard reason: revokes its
    /// previewed brief grants, publishes its tombstone, purges it and writes
    /// its receipt. Bytes it shares stay while another record holds them.
    ///
    /// With `also_same_bytes`, which only a live owner of this vault may set,
    /// every other record the preview names as holding the same blob bytes
    /// ([`DeleteEntityPreview::same_bytes_matches`]) is then erased the same
    /// way, in id order: its own live brief grants are revoked, then its own
    /// checked delete writes its tombstone, purge and receipt. In a shared
    /// vault a record another actor wrote is held, not erased, unless the
    /// reason is a GDPR request; with [`EraseOptions::veto_starter`] it starts
    /// its own `erase` act once the confirmed record is erased, and a failed
    /// start is that row's failure. Owner authority, the preview and every
    /// holder's classification are read in one snapshot before anything is
    /// destroyed. A failure on the confirmed record returns the error and
    /// erases nothing else; a later row's failure never hides an earlier
    /// completed erase. Under a GDPR request every record a legal hold names,
    /// the confirmed one included, is kept and shows why, and the rest is
    /// erased (OF-470 C5).
    ///
    /// A byte carrier (the content-addressed ASSET every holder reads its
    /// bytes through) is refused: erasing it would take the bytes from every
    /// holder at once. Erase a record that holds them instead.
    pub fn confirm_entity_erase(
        &self,
        preview: &DeleteEntityPreview,
        options: EraseOptions<'_>,
    ) -> MemoryResult<EntityEraseOutcome> {
        let (plan, shared_vault_id) = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
            if let Some(starter) = options.veto_starter {
                self.require_own_proof_in_txn(&txn, starter)?;
            }
            preview.check_before_unshare(self.vault, &txn)?;
            if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(
                &self.vault.store,
                &txn,
                &preview.entity(),
            )? && crate::blob_artifact::carrier_content_hash(&preview.entity(), &raw)?.is_some()
            {
                return Err(carrier_erase_refused());
            }
            let mut plan = Vec::new();
            if options.also_same_bytes {
                self.require_live_owner_in_txn(&txn)?;
                for (holder, hashes) in previewed_holdings(preview) {
                    plan.push(PlannedMatch {
                        hold: self.same_bytes_hold_in_txn(&txn, &holder, options.reason)?,
                        holder,
                        hashes,
                        act: None,
                    });
                }
            }
            let shared_vault_id = self
                .vault
                .shared_vault_creation_in_txn(&txn)?
                .map(|creation| creation.vault_id);
            (plan, shared_vault_id)
        };
        let kept = if options.reason == EraseReason::GdprDelete {
            let records: Vec<EntityId> = std::iter::once(preview.entity())
                .chain(plan.iter().map(|planned| planned.holder))
                .collect();
            self.keep_legally_held(&records)?
        } else {
            BTreeMap::new()
        };
        let first = if let Some(hold) = kept.get(&preview.entity()) {
            DeleteReceipt {
                existed: true,
                reason: hold.code().to_owned(),
                receipt_ref: None,
            }
        } else {
            let actor = WriteActor::new(self.actor, self.actor_class);
            for (share_id, _) in preview.shared_with() {
                self.vault.revoke_share(
                    share_id,
                    &actor,
                    self.vault.store.clock.now_recorded_at(),
                )?;
            }
            let reason = options.reason.safe_delete_reason();
            self.safe_delete_preview_checked(&preview.entity().to_hex(), reason, |txn| {
                preview
                    .check_after_unshare(self.vault, txn)
                    .map_err(Into::into)
            })?
        };
        let same_bytes = plan
            .into_iter()
            .map(|planned| {
                if let Some(&reason) = kept.get(&planned.holder) {
                    let outcome = SameBytesOutcome::Held {
                        reason,
                        act_id: None,
                    };
                    return (planned.holder, outcome);
                }
                let outcome = match (planned.hold, options.veto_starter.zip(shared_vault_id)) {
                    (Some(reason), Some((starter, vault_id))) => {
                        match self.start_held_erase(starter, vault_id, &planned) {
                            Ok(act) => SameBytesOutcome::Held {
                                reason,
                                act_id: Some(act.id),
                            },
                            Err(error) => SameBytesOutcome::Failed(error),
                        }
                    }
                    (Some(reason), None) => SameBytesOutcome::Held {
                        reason,
                        act_id: None,
                    },
                    (None, _) => self.erase_match(&planned, options.reason),
                };
                (planned.holder, outcome)
            })
            .collect();
        Ok(EntityEraseOutcome { first, same_bytes })
    }

    /// Erases the record a completed `erase` act names, once: the act is one
    /// this caller started in this vault, and its veto window has run out on
    /// the store clock with no live objection. Only that act's hold on the
    /// record is lifted; owner authority, the bytes it held and its brief
    /// grants are checked as for any same-bytes match. The delete claims the
    /// act in its linearizing write, so a retry returns that erase's receipt
    /// and never starts a second one.
    pub fn execute_completed_entity_erase(
        &self,
        owner: &AuthenticatedOwner,
        act_id: &str,
    ) -> MemoryResult<DeleteReceipt> {
        let planned = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
            self.require_own_proof_in_txn(&txn, owner)?;
            let act = self
                .vault
                .pending_authority_act_in_txn(&txn, act_id)?
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_NOT_FOUND,
                        "no such act",
                        &["Use the act id a held record returned."],
                    )
                })?;
            let held = self.held_erase_in_txn(&txn, &act)?;
            if act.execution.is_some()
                || self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(&txn, &held.holder)?
            {
                return self.executed_erase_in_txn(&txn, &held.holder, act.execution.as_ref());
            }
            if !self.vault.authority_act_completed_in_txn(&txn, &act)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "this erase's veto window is open or an owner objects",
                    &["Execute it once the window has run out with no objection."],
                ));
            }
            PlannedMatch {
                act: Some(act.id),
                ..held
            }
        };
        self.unshare_and_erase_match(&planned, EraseReason::UserHardDelete, Some(owner))
    }

    /// A held match's own `erase` act, its payload the record and the bytes the preview named.
    fn start_held_erase(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        planned: &PlannedMatch,
    ) -> MemoryResult<PendingAuthorityAct> {
        let payload = serde_json::to_vec(&HeldErase {
            v: 1,
            record: *planned.holder.as_bytes(),
            hashes: planned.hashes.clone(),
        })
        .map_err(|_| Error::InvariantViolation("erase act payload"))?;
        Ok(self
            .vault
            .start_authority_act(starter, vault_id, ERASE_ACT, payload)?)
    }

    /// The match an `erase` act names, when this caller started it in this vault.
    fn held_erase_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        act: &PendingAuthorityAct,
    ) -> MemoryResult<PlannedMatch> {
        let vault_id = self
            .vault
            .shared_vault_creation_in_txn(txn)?
            .map(|creation| creation.vault_id);
        (act.act == ERASE_ACT
            && Some(act.vault_id) == vault_id
            && act.starter == self.actor.to_hex())
        .then(|| serde_json::from_slice::<HeldErase>(&act.payload).ok())
        .flatten()
        .filter(|held| held.v == 1)
        .and_then(|held| {
            Some(PlannedMatch {
                holder: EntityId::from_bytes(held.record).ok()?,
                hashes: held.hashes,
                hold: None,
                act: None,
            })
        })
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "this act is no erase this caller started in this vault",
                &["Execute an erase act you started here."],
            )
        })
    }

    /// An erase already done: the claimed request's receipt once written, or
    /// the record's local hard delete when a recovery finished it without one.
    /// A recovery that finished a request whose claim never committed leaves
    /// the record erased and the act unclaimed; it reads as erased too.
    fn executed_erase_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: &EntityId,
        execution: Option<&ActExecution>,
    ) -> MemoryResult<DeleteReceipt> {
        let receipt = execution.and_then(|execution| execution.receipt.as_ref());
        if receipt.is_some()
            || self
                .vault
                .local_hard_delete_marker_exists_in_txn(txn, holder)?
        {
            return Ok(DeleteReceipt {
                existed: true,
                reason: SafeDeleteReason::UserHardDelete.as_str().to_owned(),
                receipt_ref: receipt.map(|receipt| format!("redaction:{receipt}")),
            });
        }
        Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "this act's erase is claimed and under way",
            &["Its deletion recovery finishes it; ask again later."],
        ))
    }

    /// Of the records a GDPR request names, the ones a legal hold keeps (C5). Each one's
    /// refusal and reason go to its hold's log, and where Oneiron hosts the bytes it is kept
    /// under a use limit (C6). One only a secret order keeps reads as completion pending (C2).
    fn keep_legally_held(
        &self,
        records: &[EntityId],
    ) -> MemoryResult<BTreeMap<EntityId, SameBytesHold>> {
        let store = &self.vault.store;
        let kind = match self.actor_class {
            EdgeActorClass::Human => LegalHoldActorKind::Owner,
            EdgeActorClass::Agent => LegalHoldActorKind::Agent,
            EdgeActorClass::System => LegalHoldActorKind::Unattributed,
        };
        let actor = HoldActor::new(kind, Some(self.actor.to_hex()));
        Ok(self.vault.with_write_txn_grouped(|txn| {
            let (_, kept) = legal_hold::split_privacy_erase_in_txn(store, txn, records, &actor)?;
            let now = store.clock.now_recorded_at();
            kept.into_iter()
                .map(|record| {
                    let target = LegalHoldTarget::Record(record);
                    let told = legal_hold::holds_on_in_txn(store, txn, &target)?
                        .iter()
                        .any(|hold| !hold.secret_at(now));
                    let hold = if told {
                        SameBytesHold::LegalHold
                    } else {
                        SameBytesHold::CompletionPending
                    };
                    Ok((record, hold))
                })
                .collect()
        })?)
    }

    /// One planned match through its own checked delete.
    fn erase_match(&self, planned: &PlannedMatch, reason: EraseReason) -> SameBytesOutcome {
        match self.unshare_and_erase_match(planned, reason, None) {
            Ok(receipt) => SameBytesOutcome::Erased(receipt),
            Err(error) => SameBytesOutcome::Failed(error),
        }
    }

    /// As for the confirmed record: the match's own live brief grants are
    /// revoked first, then every destructive transaction of its delete
    /// refuses while a grant on it is live. A match an act lifts claims that
    /// act in its delete's linearizing write, and `owner`'s proof is
    /// revalidated wherever the rest is rechecked.
    fn unshare_and_erase_match(
        &self,
        planned: &PlannedMatch,
        reason: EraseReason,
        owner: Option<&AuthenticatedOwner>,
    ) -> MemoryResult<DeleteReceipt> {
        let store = &self.vault.store;
        let check = |txn: &heed::RoTxn<'_>| {
            if let Some(owner) = owner {
                self.require_own_proof_in_txn(txn, owner)?;
            }
            self.still_erasable_in_txn(txn, planned, reason)
        };
        let claim: crate::deletion::DeletionClaim<'_> = &|txn, request, receipt| {
            let Some(act) = &planned.act else {
                return Ok(());
            };
            self.vault.claim_completed_authority_act_in_txn(
                txn,
                act,
                uuid::Uuid::from_bytes(*request).to_string(),
                receipt.map(EntityId::to_hex),
            )
        };
        let shares = {
            let txn = store.env.read_txn().map_err(crate::Error::from)?;
            check(&txn)?;
            crate::share::active_brief_shares_for(
                store,
                &txn,
                &planned.holder,
                store.clock.now_recorded_at(),
            )?
        };
        let actor = WriteActor::new(self.actor, self.actor_class);
        for (share_id, _) in shares {
            self.vault
                .revoke_share(&share_id, &actor, store.clock.now_recorded_at())?;
        }
        #[cfg(all(test, feature = "sync"))]
        if FAIL_NEXT_MATCH_AFTER_TOMBSTONE.replace(false) {
            crate::deletion::arm_fail_after_tombstone_before_purge();
        }
        self.safe_delete_claimed(
            &planned.holder.to_hex(),
            reason.safe_delete_reason(),
            |txn| {
                check(txn)?;
                if crate::share::active_brief_shares_for(
                    store,
                    txn,
                    &planned.holder,
                    store.clock.now_recorded_at(),
                )?
                .is_empty()
                {
                    Ok(())
                } else {
                    Err(Error::ConcurrentWrite("delete shares changed").into())
                }
            },
            planned.act.is_some().then_some(claim),
        )
    }

    /// The proof is this caller's own and names a live owner of this vault.
    fn require_own_proof_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<()> {
        if owner.revalidate_in_txn(self.vault, txn)? == self.actor {
            return Ok(());
        }
        Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the owner proof names another actor than this caller",
            &["Pass this caller's own owner proof."],
        ))
    }

    /// The same-bytes flag reaches records the caller did not name, so it asks for a live owner
    /// of this vault, not only deletion authority.
    fn require_live_owner_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        if crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &self.actor)? {
            return Ok(());
        }
        Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "actor {} is no live owner of this vault; the same-bytes erase is an owner's act",
                self.actor.to_hex()
            ),
            &["Erase the one record without the same-bytes flag, or ask a vault owner."],
        ))
    }

    /// `None` when this caller may erase `holder` with the record it confirmed:
    /// outside a shared vault, under a GDPR request, or when the caller wrote
    /// it. An unresolvable writer is not the caller.
    fn same_bytes_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: &EntityId,
        reason: EraseReason,
    ) -> MemoryResult<Option<SameBytesHold>> {
        if reason == EraseReason::GdprDelete {
            return Ok(None);
        }
        let shared = self
            .vault
            .shared_vault_creation_in_txn(txn)?
            .is_some_and(|creation| creation.preset != Some(SharedVaultPreset::Personal));
        if !shared
            || crate::blob_artifact::artifact_author_in_txn(self.vault, txn, holder)?
                == Some(self.actor)
        {
            return Ok(None);
        }
        Ok(Some(SameBytesHold::AnotherOwnersRecord))
    }

    /// Rechecked in the holder's own delete transactions: the caller is still a
    /// live owner, the holder still holds one of the bytes the preview named
    /// for it, and this caller may still erase it, or its completed act lifts
    /// the hold.
    fn still_erasable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        planned: &PlannedMatch,
        reason: EraseReason,
    ) -> MemoryResult<()> {
        self.require_live_owner_in_txn(txn)?;
        for hash in &planned.hashes {
            if crate::blob_artifact::content_holders_in_txn(&self.vault.store, txn, hash)?
                .contains(&planned.holder)
            {
                if planned.act.is_some()
                    || self
                        .same_bytes_hold_in_txn(txn, &planned.holder, reason)?
                        .is_none()
                {
                    return Ok(());
                }
                break;
            }
        }
        Err(Error::ConcurrentWrite("delete preview stale").into())
    }
}

impl SameBytesHold {
    /// The legal-hold log's reason code for a record a GDPR request kept.
    const fn code(self) -> &'static str {
        match self {
            Self::AnotherOwnersRecord => "another_owners_record",
            Self::LegalHold => "privacy_erase_kept",
            Self::CompletionPending => "completion_pending",
        }
    }
}

/// One other holder of the previewed bytes, classified in the planning snapshot.
struct PlannedMatch {
    holder: EntityId,
    hashes: Vec<[u8; 32]>,
    hold: Option<SameBytesHold>,
    /// The completed `erase` act that lifts its hold.
    act: Option<String>,
}

/// An `erase` act's payload.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldErase {
    v: u8,
    record: [u8; 16],
    hashes: Vec<[u8; 32]>,
}

#[cfg(all(test, feature = "sync"))]
thread_local! {
    static FAIL_NEXT_MATCH_AFTER_TOMBSTONE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Arms the delete rail's one-shot failure after a durable tombstone for the next same-bytes
/// match, not the confirmed record.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn arm_fail_next_match_after_tombstone() {
    FAIL_NEXT_MATCH_AFTER_TOMBSTONE.with(|armed| armed.set(true));
}

fn carrier_erase_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        "this record is the byte carrier its holders read through; erasing it would take the bytes from every holder",
        &[
            "Erase a record that holds these bytes; with the same-bytes flag, every holder goes and the bytes with the last.",
        ],
    )
}

/// Every other holder the preview names, sorted, with the hashes it held.
fn previewed_holdings(preview: &DeleteEntityPreview) -> BTreeMap<EntityId, Vec<[u8; 32]>> {
    let mut holdings: BTreeMap<EntityId, Vec<[u8; 32]>> = BTreeMap::new();
    for row in preview.held_bytes() {
        for holder in row.other_holders() {
            holdings
                .entry(*holder)
                .or_default()
                .push(row.content_hash());
        }
    }
    holdings
}
