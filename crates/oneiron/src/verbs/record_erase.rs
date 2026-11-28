//! The served erase of one record (OF-150 / OF-163): the shared preview
//! `vault.owner_confirm.preview` shows what an erase would take (the brief
//! grants it revokes, the records holding the same bytes, the LFS chunks it
//! shares), and `vault.records.erase_confirm` erases it under the caller's
//! own proof once they confirm that same preview. In a shared vault a record
//! another owner wrote, and the confirmed record itself where two or more
//! Owners hold the vault, starts its own `erase` act instead, which
//! `vault.shared.execute` carries out once its veto window has run out.
use serde::{Deserialize, Serialize};

use super::owner_confirm;
use crate::consent::AuthenticatedOwner;
use crate::deletion::DeleteEntityPreview;
use crate::deletion::LegalHoldKind;
use crate::deletion::LegalHoldTarget;
use crate::memory::RemainingNotice;
use crate::memory::{
    DeleteReceipt, DeleteRequestState, EraseOptions, EraseReason, Memory, MemoryError,
    MemoryResult, SameBytesHold, SameBytesOutcome,
};
use crate::{EntityId, entity_id::bytes_to_hex_lower};
use oneiron_records::memory::claims as remaining_claims;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::record_erase::RecordEraseConfirmRequest;

/// One live brief grant the erase revokes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseShare {
    pub grant: String,
    pub recipient: String,
}

/// One content hash the record holds, and the other records holding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseHeldBytes {
    pub content_hash: String,
    pub other_holders: Vec<String>,
}

/// One LFS chunk the record's object shares, and the other owners of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseLfsChunk {
    pub chunk_hash: String,
    pub other_owners: Vec<String>,
}

/// What erasing the record would take, as the shared preview shows it: the
/// record, the brief grants the erase revokes, the records holding the same
/// bytes, the LFS chunks it shares, and what `also_same_bytes` would also
/// take. The shared confirm binds it, so a record whose shares or
/// same-bytes holders changed since is refused, not erased.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordErasePreview {
    pub record: String,
    pub shared_with: Vec<EraseShare>,
    pub held_bytes: Vec<EraseHeldBytes>,
    pub lfs_chunks: Vec<EraseLfsChunk>,
    /// What `also_same_bytes` would also take.
    pub same_bytes: Vec<String>,
    /// Federation recipients may keep copies after a local erase.
    pub remote_copies_may_remain: bool,
    /// For a world whose keys this erase destroys (ARCH-0038
    /// #erase-sealed-bundles), the owner-ruled words: the world is erased now,
    /// and old backups keep only an unreadable copy until they expire. Absent
    /// for every other record, so its preview stays as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_notice: Option<String>,
    /// Beside that notice, the days within which those old backups expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_expire_within_days: Option<u32>,
    /// What the erase would leave behind that the person is told.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<RemainingNotice>,
    /// How many legal holds keep a sealed copy of this record outside the vault; shown
    /// only to the owner and only when no secrecy order hides the hold.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub legal_copies_kept: u32,
}

/// What became of one other record holding the same bytes: `erased`,
/// `held` (with its reason code, and the `erase` act it started, if any) or
/// `failed` (with the error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseSameBytesRow {
    pub record: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DeleteReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `vault.records.erase_confirm`'s answer: the confirmed record's receipt,
/// its own `erase` act when it waits on a veto window, and one row per other
/// record holding its bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEraseOutcome {
    pub first: DeleteReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_act: Option<String>,
    pub same_bytes: Vec<EraseSameBytesRow>,
    /// The check-in decision the erase ran on (2j; P24-SHAPE Q7 and Q9 = A):
    /// the Owner on their own proof, and the approved check-in of another
    /// asker it applied, with its requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
    /// The preview's notice, once the erase destroyed the world's keys now;
    /// absent while the erase waits, and for every other record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_notice: Option<String>,
    /// Beside that notice, the days within which those old backups expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_expire_within_days: Option<u32>,
    /// What the erase leaves behind that the person is told: the confirmed
    /// record's list, beside its receipt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<RemainingNotice>,
    /// How many legal holds keep a sealed copy of this record outside the vault; shown
    /// only to the owner and only when no secrecy order hides the hold.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub legal_copies_kept: u32,
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes_to_hex_lower(bytes)
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The notice an erase of a world gives, and the days it names: the world is
/// erased now, and the sealed bundles kept before it hold only an unreadable
/// copy until they expire (ARCH-0038 #erase-sealed-bundles, owner 2026-10-18).
fn world_erase_notice(world_erase: bool) -> (Option<String>, Option<u32>) {
    if !world_erase {
        return (None, None);
    }
    let days = crate::world_keys::ERASED_WORLD_BACKUP_KEEP_DAYS;
    (
        Some(format!(
            "This world is erased now. Old backups keep only an unreadable copy of it until \
             they expire, within {days} days."
        )),
        Some(days),
    )
}

/// Whether erasing `record` destroys a world's keys: it is a WORLD other than
/// the base world.
fn erases_world(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> MemoryResult<bool> {
    crate::world_keys::is_erasable_world_in_txn(&memory.vault().store, txn, record)
        .map_err(MemoryError::from)
}

/// Whether a copy of this vault lives on another machine or with other members, so an
/// erase reaches it only when that copy next syncs (H5, F9).
fn vault_syncs_in_txn(vault: &crate::Vault, txn: &heed::RoTxn<'_>) -> crate::Result<bool> {
    // This machine is a replica that reached its home at least once.
    // (`sync` owns the row, so this arm builds only with that feature.)
    #[cfg(feature = "sync")]
    if crate::sync::window_rows::LAST_SYNC
        .get(&vault.store, txn, &())?
        .is_some()
    {
        return Ok(true);
    }
    // The authority names a machine other than the serving one.
    let serving = vault.serving_machine_in_txn(txn)?;
    if vault
        .authority_view_readonly_in_txn(txn)?
        .machines
        .keys()
        .any(|machine| Some(*machine) != serving)
    {
        return Ok(true);
    }
    // A shared vault: other members hold a copy.
    if vault.shared_vault_creation_in_txn(txn)?.is_some() {
        return Ok(true);
    }
    Ok(false)
}

/// The erase-level entries P shows and R repeats, in door order, and how many legal
/// holds keep a sealed copy of `record` outside the vault: backups and exports notes
/// and the disk note always; the devices note when the record was shared or the vault
/// syncs; the provider note when the vault's settings let a model call leave the
/// device; the hold note when an owner-visible customer hold names a sealed capture of the record.
fn remaining_for_erase(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
    preview: &DeleteEntityPreview,
) -> MemoryResult<(Vec<RemainingNotice>, u32)> {
    let vault = memory.vault();
    let mut remaining = Vec::new();
    remaining.push(RemainingNotice {
        code: remaining_claims::REMAINING_BACKUPS_BEFORE_ERASE.to_owned(),
        text: remaining_claims::REMAINING_BACKUPS_BEFORE_ERASE_TEXT.to_owned(),
    });
    let disk_text = if vault.vault_pages_sealed() {
        remaining_claims::REMAINING_DISK_NOT_OVERWRITTEN_SEALED_TEXT
    } else {
        remaining_claims::REMAINING_DISK_NOT_OVERWRITTEN_PLAIN_TEXT
    };
    remaining.push(RemainingNotice {
        code: remaining_claims::REMAINING_DISK_NOT_OVERWRITTEN.to_owned(),
        text: disk_text.to_owned(),
    });
    remaining.push(RemainingNotice {
        code: remaining_claims::REMAINING_EXPORTS_BEFORE_ERASE.to_owned(),
        text: remaining_claims::REMAINING_EXPORTS_BEFORE_ERASE_TEXT.to_owned(),
    });
    if !preview.shared_with().is_empty() || vault_syncs_in_txn(vault, txn)? {
        remaining.push(RemainingNotice {
            code: remaining_claims::REMAINING_DEVICES_AND_PEERS.to_owned(),
            text: remaining_claims::REMAINING_DEVICES_AND_PEERS_TEXT.to_owned(),
        });
    }
    if crate::llm::vault_allows_provider_model_in_txn(vault, txn)? {
        remaining.push(RemainingNotice {
            code: remaining_claims::REMAINING_MODEL_PROVIDERS.to_owned(),
            text: remaining_claims::REMAINING_MODEL_PROVIDERS_TEXT.to_owned(),
        });
    }
    // The legal-copy count is shown only to the owner: a caller whose proof carries
    // no owner authority (a shared person previewing or confirming an erase)
    // counts zero, without failing the otherwise permitted erase. A store error
    // still fails the read.
    let legal_copies_kept: u32 = match owner.revalidate_in_txn(vault, txn) {
        Ok(_) => {
            let now = vault.store.clock.now_recorded_at();
            // Host orders keep no copy in this vault; a customer hold counts when its sealed
            // capture holds the record. The rows of LEGAL_HOLD_SEALED_RECORD decide when they
            // name the record (Record targets, prospective seals, inquiry copy CLAIMs): a
            // capture that landed or waits in the outbox. A Record target sealed before those
            // rows counts while the hold names any capture. A landed capture counts only while
            // this install's hold store holds its file and the hold's key: a restored hold
            // names its source's captures, whose files stayed with the source.
            let mut kept = 0u32;
            for hold in crate::store::legal_hold::holds_in_txn(&vault.store, txn)? {
                if !hold.stands()
                    || !hold.owner_may_see(now)
                    || hold.kind != LegalHoldKind::Customer
                {
                    continue;
                }
                let sealed = match crate::store::legal_hold::sealed_records::kept_copy_in_txn(
                    vault, txn, &hold, record,
                )? {
                    Some(sealed) => sealed,
                    None => {
                        hold.targets.contains(&LegalHoldTarget::Record(*record))
                            && crate::store::legal_hold::sealed_records::holds_any_capture(
                                vault, &hold,
                            )?
                    }
                };
                if sealed {
                    kept = kept.saturating_add(1);
                }
            }
            kept
        }
        Err(crate::error::Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
            _,
        ))) => 0,
        Err(other) => return Err(other.into()),
    };
    if legal_copies_kept > 0 {
        remaining.push(RemainingNotice {
            code: remaining_claims::REMAINING_LEGAL_HOLD_COPY.to_owned(),
            text: remaining_claims::REMAINING_LEGAL_HOLD_COPY_TEXT.to_owned(),
        });
    }
    Ok((remaining, legal_copies_kept))
}

fn preview_view(
    preview: &DeleteEntityPreview,
    world_erase: bool,
    remaining: Vec<RemainingNotice>,
    legal_copies_kept: u32,
) -> RecordErasePreview {
    let (old_backups_notice, old_backups_expire_within_days) = world_erase_notice(world_erase);
    RecordErasePreview {
        record: preview.entity().to_hex(),
        shared_with: preview
            .shared_with()
            .iter()
            .map(|(grant, recipient)| EraseShare {
                grant: grant.to_hex(),
                recipient: recipient.to_hex(),
            })
            .collect(),
        held_bytes: preview
            .held_bytes()
            .iter()
            .map(|row| EraseHeldBytes {
                content_hash: hex(&row.content_hash()),
                other_holders: row.other_holders().iter().map(EntityId::to_hex).collect(),
            })
            .collect(),
        lfs_chunks: preview
            .lfs_chunks()
            .iter()
            .map(|row| EraseLfsChunk {
                chunk_hash: hex(&row.chunk_hash()),
                other_owners: row.other_owners().iter().map(EntityId::to_hex).collect(),
            })
            .collect(),
        same_bytes: preview
            .same_bytes_matches()
            .iter()
            .map(EntityId::to_hex)
            .collect(),
        remote_copies_may_remain: preview.remote_copies_may_remain(),
        old_backups_notice,
        old_backups_expire_within_days,
        remaining,
        legal_copies_kept,
    }
}

/// The held row's reason code, as [`SameBytesHold`] logs it.
fn hold_code(hold: SameBytesHold) -> &'static str {
    match hold {
        SameBytesHold::AnotherOwnersRecord => "another_owners_record",
        SameBytesHold::VetoWindow => "veto_window",
    }
}

/// The erase's view twice over: the engine preview the erase runs on, and
/// the shown view the owner confirms. [`confirm_record_erase`] and the
/// shared preview call this same fn, so a confirm binds what the preview
/// showed. The caller's proof gates the legal-copy count: only an owner is
/// shown it.
pub(crate) fn record_erase_view(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> MemoryResult<(DeleteEntityPreview, RecordErasePreview)> {
    let preview = memory.preview_entity_delete(record)?;
    let (world_erase, remaining, legal_copies_kept) = {
        let txn = memory
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let world_erase = erases_world(memory, &txn, *record)?;
        let (remaining, legal_copies_kept) =
            remaining_for_erase(memory, owner, &txn, record, &preview)?;
        (world_erase, remaining, legal_copies_kept)
    };
    let view = preview_view(&preview, world_erase, remaining, legal_copies_kept);
    Ok((preview, view))
}

/// `vault.records.erase_confirm`: erases the record the caller previewed,
/// under the owner erase reason, once the preview it takes again is still
/// what they confirmed. `owner` is the caller's own proof: with it a held
/// record starts its own `erase` act. The confirm names the caller's own
/// live retained preview of this call first (FIX 12522, kept through the
/// shared row): without it the erase is refused, even when what it names is
/// fresh.
pub fn confirm_record_erase(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RecordEraseConfirmRequest,
) -> MemoryResult<RecordEraseOutcome> {
    let ask = owner_confirm::asked("vault.records.erase_confirm", &input)?;
    let (preview, view) = record_erase_view(memory, owner, &input.record)?;
    let vault = memory.vault();
    owner_confirm::admit(vault, owner, ask, &view)?;
    // The confirmed view names the old backups exactly when this erase
    // destroys a world's keys.
    let world_erase = view.old_backups_notice.is_some();
    // An asker's approved check-in the Owner applies (2j; P24-SHAPE Q7 = A)
    // is checked before the erase writes and spent, on the Owner's live
    // proof, in the writer that starts its `erase` act or, just before the
    // record's delete, in one of its own that finds the delete rail admits
    // the record: an erase refused before then leaves the approval unspent (FIX
    // CHECK-IN-SPEND-BEFORE-RECORD-ERASE). The shared confirm, the veto
    // window, the legal holds and the Owner proof the erase asks for all
    // still hold; an answer is no proof of its own. The decision goes on
    // each `erase` act a veto window starts, and from there on its
    // completion receipt (P24-SHAPE Q9 = A).
    let applied = super::shared::check_in_ref(input.check_in_ref.as_deref())?.map(|id| {
        crate::check_in::AppliedCheckIn {
            id,
            verb: "vault.records.erase_confirm",
            effect_digest: crate::check_in::record_erase_effect_digest(
                &input.record,
                input.also_same_bytes,
            ),
        }
    });
    let (outcome, decision) = memory.confirm_entity_erase_with_check_in(
        &preview,
        EraseOptions {
            reason: EraseReason::OwnerErase,
            also_same_bytes: input.also_same_bytes,
            veto_starter: Some(owner),
        },
        applied.as_ref(),
    )?;
    // Only an erase applied now destroyed the world's keys and freed the
    // record's disk space; one that waits on a veto window or a hold has not
    // erased it yet.
    let applied_now = outcome.first.state == DeleteRequestState::Applied;
    let (old_backups_notice, old_backups_expire_within_days) =
        world_erase_notice(world_erase && applied_now);
    Ok(RecordEraseOutcome {
        check_in: Some(decision),
        old_backups_notice,
        old_backups_expire_within_days,
        // The erase answer's top-level list is the confirmed record's own
        // followed by the erase-level entries of the retaken view, so R
        // shows what P showed. A pending R leaves the disk note out: P says
        // what the erase will do, and the disk is freed only once it applies
        // (H5-R2-PENDING-ERASE-DISK-WORDING = A).
        remaining: {
            let mut remaining = outcome.first.remaining.clone();
            remaining.extend(view.remaining.into_iter().filter(|notice| {
                applied_now || notice.code != remaining_claims::REMAINING_DISK_NOT_OVERWRITTEN
            }));
            remaining
        },
        legal_copies_kept: view.legal_copies_kept,
        first: outcome.first,
        first_act: outcome.first_act,
        same_bytes: outcome
            .same_bytes
            .into_iter()
            .map(|(record, row)| {
                let record = record.to_hex();
                match row {
                    SameBytesOutcome::Erased(receipt) => EraseSameBytesRow {
                        record,
                        outcome: "erased".to_owned(),
                        receipt: Some(receipt),
                        reason: None,
                        act_id: None,
                        error: None,
                    },
                    SameBytesOutcome::Held { reason, act_id } => EraseSameBytesRow {
                        record,
                        outcome: "held".to_owned(),
                        receipt: None,
                        reason: Some(hold_code(reason).to_owned()),
                        act_id,
                        error: None,
                    },
                    SameBytesOutcome::Failed(error) => EraseSameBytesRow {
                        record,
                        outcome: "failed".to_owned(),
                        receipt: None,
                        reason: None,
                        act_id: None,
                        error: Some(error.to_string()),
                    },
                }
            })
            .collect(),
    })
}

/// `vault.records.erase_confirm` on an embedded handle: the embedded owner's
/// own erase.
pub fn confirm_record_erase_embedded(
    memory: &Memory<'_>,
    input: RecordEraseConfirmRequest,
) -> MemoryResult<RecordEraseOutcome> {
    let owner = memory.embedded_owner("vault.records.erase_confirm")?;
    confirm_record_erase(memory, &owner, input)
}
