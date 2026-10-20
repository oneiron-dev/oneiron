//! A cold managed restore's escrow recipients (LC FIX 5384/5385; the
//! contract is lanes/l14/t3/restore-contract.md): the restored key is
//! wrapped to the plan's fresh managed and break-glass recipients, then the
//! recipients whose secrets the restore's key release used are retired, so
//! a released secret never unlocks the vault again.
//!
//! One consumed-once capability carries the authority; it is minted only
//! where the restore verified its artifact, its content and its custody and
//! fenced the old writer, before the vault is kept. It touches escrow wraps
//! of the two managed roles alone, never an owner's wrap, and acts as no
//! owner (FIX 2222; canon C24:611-615). The full lists are checked before
//! anything is written; then every fresh wrap is added, then exactly the
//! released labels retire, and the key keeps a wrap. A label the lineage's
//! custody log retired before, which an older image still carries, retires
//! with them. With a custody head each plan retirement is journaled in the
//! custody log at the takeover writer epoch before the restore is kept;
//! with none it is the restored key header's alone, and said so.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, PoisonError};

use oneiron_crypto::HybridPublicKey;

use super::{
    ESCROW_RETIRED, ESCROW_SPOOLED, EscrowRetirement, STATE, StoredWrap, VaultKeyWrapKind, WRAPS,
    WrapTransition, check_name,
};
use crate::recovery::checkpoint::{
    AddedRecipient, EscrowRole, RecipientAdmissionFacts, RecipientRetirementDisposition, Rejected,
    RestoreAdmissionReason as R, RestorePlan, RetiredBy, RetiredRecipient, because,
};
use crate::store::RecipientRetirement;
use crate::world_keys::{OpenedDataKey, refused};
use crate::{EntityId, Vault};

/// Where a cold managed restore's recipient retirements are made durable.
pub(crate) enum RecipientCustody {
    /// In the landed custody log, at this takeover writer epoch.
    Takeover(u64),
    /// In the restored key header alone, with the receipt's note.
    LocalOnly(&'static str),
}

/// The authority a cold managed restore holds over the restored key's
/// managed escrow wraps: no `Clone`, `Serialize` or `Default`, spent once
/// by [`Vault::spend_restore_capability`]. Only
/// [`Vault::restore_checkpoint_admitted`] mints one, after verification and
/// the takeover fence, before keep.
pub(crate) struct RestoreAdmissionCapability {
    source: [u8; 32],
    restore_id: String,
    plan_digest: [u8; 32],
    released: Vec<crate::recovery::checkpoint::ReleasedRecipient>,
    fresh: Vec<crate::recovery::checkpoint::FreshRecipient>,
    custody: RecipientCustody,
    /// What the admitted custody log retired before this restore.
    retired_before: Vec<RecipientRetirement>,
}

impl RestoreAdmissionCapability {
    /// The capability for `plan` over the restored vault `source`.
    pub(crate) fn mint(
        source: [u8; 32],
        plan: &RestorePlan,
        custody: RecipientCustody,
        retired_before: Vec<RecipientRetirement>,
    ) -> Self {
        Self {
            source,
            restore_id: plan.restore_id.clone(),
            plan_digest: plan.plan_digest,
            released: plan.released.clone(),
            fresh: plan.fresh.clone(),
            custody,
            retired_before,
        }
    }
}

/// `<role>.<first 16 hex of the fingerprint>`.
fn bound_label(role: EscrowRole, fingerprint: &[u8; 32]) -> String {
    format!(
        "{}.{}",
        role.label_prefix(),
        &blake3::Hash::from(*fingerprint).to_hex()[..16]
    )
}

/// The fingerprint prefix a managed or break-glass label names, if it is
/// one.
fn label_prefix_of(label: &str) -> Option<&str> {
    let (role, prefix) = label.split_once('.')?;
    matches!(role, "managed" | "break-glass").then_some(prefix)
}

/// The id of escrow wrap `label`.
fn escrow_id(label: &str) -> String {
    VaultKeyWrapKind::Escrow {
        label: label.to_owned(),
    }
    .id()
}

fn binding_invalid(reason: &'static str) -> Rejected {
    Rejected::new(R::RecipientBindingInvalid, refused(reason))
}

fn reused(reason: &'static str) -> Rejected {
    Rejected::new(R::RecipientReused, refused(reason))
}

/// One fresh recipient, checked: its label, role, fingerprint and key.
struct Fresh {
    label: String,
    role: EscrowRole,
    fingerprint: [u8; 32],
    key: HybridPublicKey,
}

/// One label the restore retires, and why.
struct Retiring {
    label: String,
    fingerprint: Option<[u8; 32]>,
    by: RetiredBy,
    epoch: Option<u64>,
}

impl RestoreAdmissionCapability {
    /// Every fresh recipient bound to its label by its own key, and every
    /// released one by its fingerprint; no duplicate, and no fresh one any
    /// released recipient's.
    fn checked_lists(&self) -> Result<Vec<Fresh>, Rejected> {
        let mut labels = BTreeSet::new();
        let mut prints = BTreeSet::new();
        for released in &self.released {
            check_name(&released.label).map_err(because(R::RecipientBindingInvalid))?;
            if released.label != bound_label(released.role, &released.fingerprint) {
                return Err(binding_invalid(
                    "a released recipient's label is not its role and fingerprint",
                ));
            }
            if !labels.insert(released.label.clone()) || !prints.insert(released.fingerprint) {
                return Err(reused("the plan names a released recipient twice"));
            }
        }
        let mut fresh = Vec::with_capacity(self.fresh.len());
        for recipient in &self.fresh {
            let key = HybridPublicKey::from_bytes(&recipient.public_key)
                .map_err(|_| binding_invalid("a fresh recipient is not a hybrid public key"))?;
            let fingerprint = *blake3::hash(&recipient.public_key).as_bytes();
            check_name(&recipient.label).map_err(because(R::RecipientBindingInvalid))?;
            if recipient.label != bound_label(recipient.role, &fingerprint) {
                return Err(binding_invalid(
                    "a fresh recipient's label is not its role and key's fingerprint",
                ));
            }
            if !labels.insert(recipient.label.clone()) || !prints.insert(fingerprint) {
                return Err(reused(
                    "a fresh recipient is a released one, or named twice",
                ));
            }
            fresh.push(Fresh {
                label: recipient.label.clone(),
                role: recipient.role,
                fingerprint,
                key,
            });
        }
        Ok(fresh)
    }
}

impl Vault {
    /// Spends `capability` on this restored vault, holding `key`, the data
    /// key it restored under: the checks, then one transaction that adds
    /// every fresh escrow wrap and retires exactly the released labels (and
    /// any the custody log retired before), then, with a custody head, each
    /// plan retirement journaled at the takeover writer epoch.
    pub(crate) fn spend_restore_capability(
        &self,
        capability: RestoreAdmissionCapability,
        key: &OpenedDataKey,
    ) -> Result<RecipientAdmissionFacts, Rejected> {
        let cap = capability;
        if cap.source != self.vault_key_vault_id()
            || cap.restore_id.is_empty()
            || cap.plan_digest == [0; 32]
        {
            return Err(Rejected::new(
                R::RetirementAuthorityInvalid,
                refused("the restore's recipient authority is not this restore's"),
            ));
        }
        let fresh = cap.checked_lists()?;
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        // The restored key is held, as its rows name it, to seal the wraps.
        if STATE
            .get(&self.store, &txn, &())?
            .is_none_or(|state| state.commitment != key.commitment())
        {
            return Err(Rejected::new(
                R::DataKeyMismatch,
                refused("the restored vault's data key is not the delivered one"),
            ));
        }
        *self
            .world_keys
            .vault_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(key.data_key()));
        let retired_labels: BTreeSet<String> = ESCROW_RETIRED
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        let held: BTreeMap<String, StoredWrap> =
            WRAPS.scan(&self.store, &txn)?.into_iter().collect();
        drop(txn);
        // A fresh recipient never reuses a retired identity, under any label.
        let retired_prefixes: BTreeSet<&str> = retired_labels
            .iter()
            .map(String::as_str)
            .chain(cap.retired_before.iter().map(|fact| fact.label.as_str()))
            .filter_map(label_prefix_of)
            .collect();
        for recipient in &fresh {
            let hex = blake3::Hash::from(recipient.fingerprint).to_hex();
            if retired_labels.contains(&recipient.label)
                || retired_prefixes.contains(&hex[..16])
                || cap
                    .retired_before
                    .iter()
                    .any(|fact| fact.fingerprint == recipient.fingerprint)
            {
                return Err(reused(
                    "a fresh recipient was released and retired before: name a new one",
                ));
            }
        }
        let mut retiring: Vec<Retiring> = cap
            .released
            .iter()
            .map(|released| Retiring {
                label: released.label.clone(),
                fingerprint: Some(released.fingerprint),
                by: RetiredBy::Plan,
                epoch: Some(released.epoch),
            })
            .collect();
        // An older image's wrap of a label the custody log retired since.
        for fact in &cap.retired_before {
            if held.contains_key(&escrow_id(&fact.label))
                && retiring.iter().all(|r| r.label != fact.label)
            {
                retiring.push(Retiring {
                    label: fact.label.clone(),
                    fingerprint: Some(fact.fingerprint),
                    by: RetiredBy::CustodyLog,
                    epoch: None,
                });
            }
        }
        let removed = retiring
            .iter()
            .filter(|r| held.contains_key(&escrow_id(&r.label)))
            .count();
        let added = fresh
            .iter()
            .filter(|f| !held.contains_key(&escrow_id(&f.label)))
            .count();
        if removed > 0 && held.len() + added <= removed {
            return Err(Rejected::new(
                R::LastWrap,
                refused("the last vault key wrap stays: add another before retiring this one"),
            ));
        }
        let transition = self.begin_wrap_transition()?;
        let retired = self.try_with_write_txn(|txn| {
            self.change_recipients_in_txn(txn, &transition, &fresh, &retiring)
        })?;
        transition.finish()?;
        let wraps: BTreeMap<String, StoredWrap> = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            WRAPS.scan(&self.store, &txn)?.into_iter().collect()
        };
        let added = fresh
            .into_iter()
            .map(|recipient| {
                let wrap_id = escrow_id(&recipient.label);
                let report_id = wraps.get(&wrap_id).map_or_else(String::new, |stored| {
                    blake3::hash(&stored.envelope).to_hex().to_string()
                });
                AddedRecipient {
                    label: recipient.label,
                    role: recipient.role,
                    fingerprint: recipient.fingerprint,
                    wrap_id,
                    report_id,
                }
            })
            .collect();
        let disposition = match cap.custody {
            RecipientCustody::Takeover(epoch) => {
                let facts = retired
                    .iter()
                    .filter(|retired| retired.retired_by == RetiredBy::Plan)
                    .map(|retired| {
                        let receipt = EntityId::from_hex(&retired.receipt.receipt_id)?;
                        Ok(RecipientRetirement {
                            label: retired.label.clone(),
                            fingerprint: retired.fingerprint.unwrap_or_default(),
                            receipt: *receipt.as_bytes(),
                        })
                    })
                    .collect::<crate::Result<Vec<_>>>()?;
                let seqs = self.store.journal_recipient_retirements(&facts, epoch)?;
                RecipientRetirementDisposition::Journaled { epoch, seqs }
            }
            RecipientCustody::LocalOnly(note) => RecipientRetirementDisposition::LocalOnly { note },
        };
        Ok(RecipientAdmissionFacts {
            added,
            retired,
            disposition,
        })
    }

    /// The one transaction of [`Self::spend_restore_capability`]: every
    /// fresh wrap added, the mirror staged with the committed wraps and the
    /// new ones, then each retiring label's wrap removed and its receipt
    /// kept (an earlier receipt for the label stands).
    fn change_recipients_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        transition: &WrapTransition<'_>,
        fresh: &[Fresh],
        retiring: &[Retiring],
    ) -> Result<Vec<RetiredRecipient>, Rejected> {
        for recipient in fresh {
            self.put_vault_key_escrow_in_txn(txn, transition, &recipient.label, &recipient.key)?
                .ok_or_else(|| {
                    Rejected::new(R::DataKeyMismatch, refused("the vault has no data key"))
                })?;
        }
        transition.stage(|| self.staged_wraps_in_txn(txn, None))?;
        let retired_at = self.instant_in_txn(txn)?.secs();
        let mut retired = Vec::with_capacity(retiring.len());
        for retiring in retiring {
            let id = escrow_id(&retiring.label);
            let removed_wrap = WRAPS.get(&self.store, txn, &id)?.is_some();
            if removed_wrap {
                WRAPS.delete(&self.store, txn, &id)?;
                ESCROW_SPOOLED.delete(&self.store, txn, &id)?;
            }
            let receipt = match ESCROW_RETIRED.get(&self.store, txn, &retiring.label)? {
                Some(receipt) => receipt,
                None => {
                    let receipt = EscrowRetirement {
                        receipt_id: self.store.clock.entity_id()?.to_hex(),
                        label: retiring.label.clone(),
                        removed_wrap,
                        retired_at,
                    };
                    ESCROW_RETIRED.put(&self.store, txn, &retiring.label, &receipt)?;
                    receipt
                }
            };
            retired.push(RetiredRecipient {
                label: retiring.label.clone(),
                fingerprint: retiring.fingerprint,
                retired_by: retiring.by,
                recipient_epoch: retiring.epoch,
                receipt,
            });
        }
        Ok(retired)
    }
}
