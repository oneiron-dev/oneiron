//! The owner's five answers to a found key: rotate (the rotate door settles
//! it), delete, grant, not a secret and kept as text. Each is owner-only,
//! checked at the owner tier in the transaction that acts, and each leaves its
//! receipt on the key.

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use zeroize::{Zeroize, Zeroizing};

use super::{FOUND, FoundKey, FoundKeyAction, FoundKeyCard, FoundKeySettled, FoundKeys};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::deletion::SafeDeleteReason;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::secret_custody::doors::{
    read_secret_custody_admission_in_txn, read_secret_custody_in_txn,
};
use crate::secret_custody::reveal::{
    not_active, resolve_handle_in_txn, reveal_bound, reveal_connection, unknown,
};
use crate::secret_custody::types::SecretCustodyStatus;
use crate::secret_custody::{put_secret_custody_in_txn, read_secret_custody_meta_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, Vault, entity_revision, live_entity_row_in_txn};
use oneiron_contracts::memory::MemoryResult;

/// Gate reason code: the owner ruled a found key no secret.
pub const FOUND_KEY_REASON_NOT_A_SECRET: &str = "gate.secret.found_key.not_a_secret";
/// Gate reason code: the owner kept a found key as text by choice.
pub const FOUND_KEY_REASON_KEPT_AS_TEXT: &str = "gate.secret.found_key.kept_as_text";

/// The Gate content kind of a found-key ruling.
const FOUND_KEY_CONTENT_KIND: &str = "secret_found_key";

/// How the delete answer removes the record that held a key: a hard delete,
/// whose body is purged and whose redaction receipt is the answer's. Canon
/// names no tier; a record that held a key keeps no shell of it.
const FOUND_KEY_DELETE: SafeDeleteReason = SafeDeleteReason::UserHardDelete;

pub(crate) use crate::file_secret_marks::HANDLE_TEXT_OPEN;

/// The text each record was indexed with, by field.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

impl Vault {
    /// Grants `agent` reveals of a found key's class: one standing grant on
    /// the 2a bound, that agent's connection × the key's custody class ×
    /// `project` (no project: reveals asked outside any), until the owner
    /// revokes it. The grant also opens the agent's sight of a marked file
    /// whose keys it covers. The consent door writes its receipt.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's. [`Error::EntityNotFound`] for a handle no notice names.
    /// [`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive)
    /// for a key no longer active. [`GateError::InvalidConsentBound`] for a
    /// key the owner ruled no secret or kept as text.
    pub fn grant_found_key(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
        agent: &EntityId,
        project: Option<&EntityId>,
    ) -> Result<FoundKeySettled> {
        self.with_write_txn_grouped(|txn| {
            let actor = live_owner_in_txn(self, owner, txn, "only the vault owner grants a key")?;
            let mut found = Located::find_in_txn(&self.store, txn, handle)?;
            found.refuse_ruled()?;
            let rec = read_secret_custody_admission_in_txn(&self.store, txn, &found.custody)?
                .ok_or_else(|| unknown(&found.handle))?;
            if rec.status != SecretCustodyStatus::Active {
                return Err(not_active(&found.handle));
            }
            let bound = reveal_bound(&reveal_connection(agent), rec.class, project)?;
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
            let settled = FoundKeySettled {
                action: FoundKeyAction::Grant,
                by: Some(actor),
                at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
                receipt: gate_ref(receipt.decision_id()),
                grant_ref: receipt.grant_ref(),
            };
            found.settle(&self.store, txn, settled.clone())?;
            Ok(settled)
        })
    }

    /// Deletes the record or file a found key sits in, through the owner's
    /// delete door ([`crate::Memory::safe_delete`], a hard delete with its
    /// redaction receipt), and settles every key found there. The key's
    /// custody record stays: rotate or revoke it on its own.
    ///
    /// # Errors
    /// What the delete door returns; [`GateError::ConsentOwnerNotAuthenticated`]
    /// when the proof is not the live owner's; [`Error::EntityNotFound`] for a
    /// handle no notice names; [`GateError::InvalidConsentBound`] for a key
    /// found outside any record (a side row), or one ruled no secret or kept as text.
    pub fn delete_found_key_record(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
    ) -> MemoryResult<FoundKeySettled> {
        let (actor, record) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let actor = live_owner_in_txn(self, owner, &txn, "only the vault owner deletes it")?;
            let found = Located::find_in_txn(&self.store, &txn, handle)?;
            found.refuse_ruled()?;
            if !is_record_place(&found.key().place) {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "this key was found outside any record; there is none to delete",
                ))
                .into());
            }
            (actor, found.record)
        };
        let deleted = self
            .memory(actor, EdgeActorClass::Human)
            .safe_delete(&record.to_hex(), FOUND_KEY_DELETE)?;
        let settled = FoundKeySettled {
            action: FoundKeyAction::Delete,
            by: Some(actor),
            at: self.store.clock.now_recorded_at(),
            receipt: deleted
                .receipt_ref
                .unwrap_or_else(|| format!("delete:{}", record.to_hex())),
            grant_ref: None,
        };
        self.with_write_txn_grouped(|txn| {
            if let Some(mut found) = FOUND.get(&self.store, txn, &record)? {
                for key in found.keys.iter_mut().filter(|key| !key.kept_by_owner()) {
                    key.settled = Some(settled.clone());
                }
                FOUND.put(&self.store, txn, &record, &found)?;
            }
            Ok(())
        })?;
        Ok(settled)
    }

    /// The owner overrules the scan: a found key is no secret. In one write
    /// transaction the ruling is kept on the key (so the write door no longer
    /// reads the value as a hit in that record), the custody record is
    /// revoked with its value kept, which that screen reads (CALLS
    /// CUSTODY_REVOKE_ERASE), the record's body or text field gets the value
    /// back where the mask left its handle, or the file's mark drops the key,
    /// and a Gate record keeps the ruling. For a repository finding, the ruling
    /// leaves its exact bytes, history and marks unchanged; the publication
    /// gate reads the custody-bound ruling. A portable record's revocation
    /// reaches the owner's other machines as a custody revoke request this
    /// install carries and enacts, with its revoked transition (WILL L04 row
    /// 04).
    ///
    /// A key found in a record's body, in one of its text fields, in a claim
    /// (FIX 2649, FIX 11882), in a file or by a repository receive is ruled
    /// here; other rows outside the entity tables keep their handles. A
    /// repository finding supports only the not-a-secret ruling, not keeping
    /// a live secret as text. A MACHINE claim whose
    /// signed history owns its body keeps its handle too: no door re-signs
    /// a stored claim. The revoke's owner act records
    /// `surface`, where his request reached this install: audit only (FIX
    /// 4650). The install key loads as the revoke door's does: when it is not
    /// available here the ruling still stands, and its revoke's carry waits
    /// for the next pass that can sign (CALLS CUSTODY_REVOKE_PENDING_CARRY,
    /// FIX 5407).
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's. [`Error::EntityNotFound`] for a handle no notice names.
    /// [`GateError::InvalidConsentBound`] for a key already ruled, a place
    /// that cannot take its value back, a key whose value a revoke erased,
    /// or a value that is not text going back into text. An install key that
    /// fails to load for a reason other than keys not available here. What
    /// the record's write door returns.
    pub fn rule_found_key_not_a_secret(
        &self,
        owner: &AuthenticatedOwner,
        surface: crate::authority::ActSurface,
        handle: &str,
    ) -> Result<FoundKeySettled> {
        self.rule_found_key_text(owner, surface, handle, FoundKeyAction::NotASecret)
    }

    /// Keeps a found key's span as text by the owner's explicit choice. The
    /// value stays a secret: this is not a false-hit ruling. The marked
    /// record's value is restored and screened from later sweeps exactly as
    /// [`Self::rule_found_key_not_a_secret`] does, while the distinct action,
    /// revoke cause and Gate reason record the owner's different intent.
    pub fn keep_found_key_as_text(
        &self,
        owner: &AuthenticatedOwner,
        surface: crate::authority::ActSurface,
        handle: &str,
    ) -> Result<FoundKeySettled> {
        self.rule_found_key_text(owner, surface, handle, FoundKeyAction::KeptAsText)
    }

    fn rule_found_key_text(
        &self,
        owner: &AuthenticatedOwner,
        surface: crate::authority::ActSurface,
        handle: &str,
        action: FoundKeyAction,
    ) -> Result<FoundKeySettled> {
        let (reason, cause, erased) = match action {
            FoundKeyAction::NotASecret => (
                FOUND_KEY_REASON_NOT_A_SECRET,
                crate::secret_rotation::RevokeCause::RuledNoSecret,
                concat!(
                    "this key's value was erased by an earlier revoke, so it can't be marked ",
                    "not-a-secret; if the value appears again, the scanner's new finding can be ",
                    "marked not-a-secret"
                ),
            ),
            FoundKeyAction::KeptAsText => (
                FOUND_KEY_REASON_KEPT_AS_TEXT,
                crate::secret_rotation::RevokeCause::KeptAsText,
                concat!(
                    "this key's value was erased by an earlier revoke, so it can't be kept as ",
                    "text; if the value appears again, the scanner's new finding can be kept as ",
                    "text"
                ),
            ),
            _ => {
                return Err(Error::InvariantViolation(
                    "a found-key text ruling names neither kept-text action",
                ));
            }
        };
        self.load_signing_for_revoke()?;
        let (settled, carried) = self.with_write_txn_grouped(|txn| {
            let actor = live_owner_in_txn(self, owner, txn, "only the vault owner rules on it")?;
            let mut found = Located::find_in_txn(&self.store, txn, handle)?;
            found.refuse_ruled()?;
            let place = found.key().place.clone();
            let field = place.strip_prefix("text:");
            let repo_false_positive =
                place == "repo:receive-pack" && action == FoundKeyAction::NotASecret;
            if place != "body"
                && place != "file"
                && place != "claim"
                && field.is_none()
                && !repo_false_positive
            {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "only a key found in a record's body, its text, a claim or a file takes \
                     its value back",
                )));
            }
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut rec = read_secret_custody_in_txn(&self.store, txn, &found.custody)?
                .ok_or_else(|| unknown(&found.handle))?;
            let value = Zeroizing::new(std::mem::take(&mut rec.value_bytes));
            // A revoke erased the value (CALLS CUSTODY_REVOKE_ERASE): there
            // is none to put back or to screen. The ruling stays open on the
            // next finding of the same value.
            if rec.status == SecretCustodyStatus::Revoked && value.is_empty() {
                return Err(Error::Gate(GateError::InvalidConsentBound(erased)));
            }
            let revoked = self.revoke_secret_in_txn(txn, &rec.name, cause, at)?;
            let decision =
                append_ruling_in_txn(self, txn, actor, &found, &place, reason, revoked.receipt_id)?;
            let settled = FoundKeySettled {
                action,
                by: Some(actor),
                at,
                receipt: gate_ref(decision),
                grant_ref: None,
            };
            // The ruling stands before the record is written again.
            found.settle(&self.store, txn, settled.clone())?;
            if place == "file" {
                drop_file_key_in_txn(self, txn, &found.record, &found.custody)?;
            } else if place == "claim" {
                restore_claim_in_txn(self, txn, &found.record, &found.handle, &value)?;
            } else if let Some(field) = field {
                restore_text_in_txn(self, txn, &found.record, field, &found.handle, &value)?;
            } else if place == "body" {
                restore_body_in_txn(self, txn, &found.record, &found.handle, &value)?;
            }
            // The ruling's surface is where the request reached this
            // install: audit only.
            let carried = self.carry_custody_revoke_in_txn(txn, actor, surface, &rec.name, at)?;
            Ok((settled, carried))
        })?;
        self.mirror_custody_change(&carried);
        Ok(settled)
    }

    /// Re-enters the kept value of a found key the owner ruled no secret or
    /// kept as text, the way out of `credential_leaf_unreadable` for it (FIX 7404): while
    /// its custody key does not open the value, every batch write to the
    /// record it was found in answers that, and no other door reaches a
    /// revoked record's value. `value` is sealed again at the record's
    /// generation, under a key minted here when custody holds none, and the
    /// ruling stands as it was, so the write door again reads `value` as no
    /// hit in that record. The owner enters it as it sits there; nothing can
    /// compare it with the value that no longer opens. A key still active
    /// (a mask-on-write lift) is re-entered, or reissued at its provider and
    /// entered, through the rotate door. Returns the standing ruling.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's. [`Error::EntityNotFound`] for a handle no notice names.
    /// [`GateError::InvalidConsentBound`] for an empty value, or a key the
    /// owner has not ruled no secret or kept as text. `credential_custody_unavailable` when
    /// custody cannot take the value's key. What the custody write returns.
    pub fn reenter_found_key_value(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
        value: &[u8],
    ) -> Result<FoundKeySettled> {
        if value.is_empty() {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "a re-entered value must not be empty",
            )));
        }
        self.with_write_txn_grouped(|txn| {
            live_owner_in_txn(
                self,
                owner,
                txn,
                "only the vault owner re-enters a kept value",
            )?;
            let found = Located::find_in_txn(&self.store, txn, handle)?;
            let settled = match &found.key().settled {
                Some(settled)
                    if matches!(
                        settled.action,
                        FoundKeyAction::NotASecret | FoundKeyAction::KeptAsText
                    ) =>
                {
                    settled.clone()
                }
                _ => {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "only a key the owner ruled no secret or kept as text re-enters its \
                         kept value here; rotate any other key to re-enter or reissue it",
                    )));
                }
            };
            let mut rec = read_secret_custody_meta_in_txn(&self.store, txn, &found.custody)?
                .ok_or_else(|| unknown(&found.handle))?;
            rec.value_bytes = value.to_vec();
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let written = put_secret_custody_in_txn(self, txn, &found.custody, &rec, at);
            rec.value_bytes.zeroize();
            written?;
            Ok(settled)
        })
    }
}

/// Settles the found key `custody` holds, if a mask found it and the owner
/// has not chosen a kept-text outcome: the rotate door's seam.
pub(crate) fn settle_found_key_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    custody: &EntityId,
    settled: FoundKeySettled,
) -> Result<()> {
    let Some(origin) = crate::batch::secret_scan::mask_origin_in_txn(store, txn, custody)? else {
        return Ok(());
    };
    let Some(mut found) = FOUND.get(store, txn, &origin.record)? else {
        return Ok(());
    };
    let Some(key) = found
        .keys
        .iter_mut()
        .find(|key| key.custody == *custody && !key.kept_by_owner())
    else {
        return Ok(());
    };
    key.settled = Some(settled);
    FOUND.put(store, txn, &origin.record, &found)
}

/// Whether the owner ruled the found key custody record `custody` holds no
/// secret: the one record a revoke leaves its bytes (CALLS
/// CUSTODY_REVOKE_ERASE), which the found-key screen reads.
pub(crate) fn ruled_no_secret_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &EntityId,
) -> Result<bool> {
    kept_action_in_txn(store, txn, custody, FoundKeyAction::NotASecret)
}

/// Whether the owner kept this found key as text by choice: its revoke also
/// leaves the value for the found-key screen.
pub(crate) fn kept_as_text_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &EntityId,
) -> Result<bool> {
    kept_action_in_txn(store, txn, custody, FoundKeyAction::KeptAsText)
}

fn kept_action_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &EntityId,
    action: FoundKeyAction,
) -> Result<bool> {
    let Some(origin) = crate::batch::secret_scan::mask_origin_in_txn(store, txn, custody)? else {
        return Ok(false);
    };
    Ok(FOUND.get(store, txn, &origin.record)?.is_some_and(|found| {
        found.keys.iter().any(|key| {
            key.custody == *custody
                && key
                    .settled
                    .as_ref()
                    .is_some_and(|settled| settled.action == action)
        })
    }))
}

/// One found key as the owner reads it, with what they may still do.
pub(super) fn card_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: &EntityId,
    key: &FoundKey,
) -> Result<FoundKeyCard> {
    let rec = read_secret_custody_admission_in_txn(&vault.store, txn, &key.custody)?;
    let mut actions = Vec::new();
    if !key.kept_by_owner() {
        let status = rec.as_ref().map(|rec| rec.status);
        if status == Some(SecretCustodyStatus::Active) {
            actions.extend([FoundKeyAction::Rotate, FoundKeyAction::Grant]);
        }
        if is_record_place(&key.place)
            && live_entity_row_in_txn(&vault.store, txn, record)?.is_live()
        {
            actions.push(FoundKeyAction::Delete);
        }
        if (matches!(key.place.as_str(), "body" | "file" | "claim")
            || key.place.starts_with("text:"))
            && status.is_some_and(|status| status != SecretCustodyStatus::Revoked)
        {
            actions.extend([FoundKeyAction::NotASecret, FoundKeyAction::KeptAsText]);
        } else if key.place == "repo:receive-pack"
            && status.is_some_and(|status| status != SecretCustodyStatus::Revoked)
        {
            actions.push(FoundKeyAction::NotASecret);
        }
    }
    let label = crate::secret_custody::secret_handle_label_in_txn(&vault.store, txn, &key.custody)?
        .map(|label| label.label);
    let suggested_label = crate::secret_custody::suggested_secret_handle_label_in_txn(
        &vault.store,
        txn,
        &key.custody,
    )?;
    Ok(FoundKeyCard {
        handle: key.handle.clone(),
        name: rec.map(|rec| rec.name).unwrap_or_default(),
        label,
        suggested_label,
        kind: key.kind().to_owned(),
        place: key.place.clone(),
        found_at: key.found_at,
        settled: key.settled.clone(),
        actions,
    })
}

/// A found key, by its handle: the record it was found in, that record's
/// keys, and which one it is.
struct Located {
    record: EntityId,
    found: FoundKeys,
    at: usize,
    custody: EntityId,
    handle: String,
}

impl Located {
    fn find_in_txn(store: &Store, txn: &RoTxn<'_>, handle: &str) -> Result<Self> {
        let (handle, custody) = resolve_handle_in_txn(store, txn, handle)?;
        let origin = crate::batch::secret_scan::mask_origin_in_txn(store, txn, &custody)?
            .ok_or(Error::EntityNotFound)?;
        let found = FOUND
            .get(store, txn, &origin.record)?
            .ok_or(Error::EntityNotFound)?;
        let at = found
            .keys
            .iter()
            .position(|key| key.custody == custody)
            .ok_or(Error::EntityNotFound)?;
        Ok(Self {
            record: origin.record,
            found,
            at,
            custody,
            handle,
        })
    }

    fn key(&self) -> &FoundKey {
        &self.found.keys[self.at]
    }

    fn refuse_ruled(&self) -> Result<()> {
        if self.key().ruled_no_secret() {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "the owner ruled this key no secret; its custody record is revoked",
            )));
        }
        if self.key().kept_as_text() {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "the owner kept this key as text; its custody record is revoked",
            )));
        }
        Ok(())
    }

    fn settle(
        &mut self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        settled: FoundKeySettled,
    ) -> Result<()> {
        self.found.keys[self.at].settled = Some(settled);
        FOUND.put(store, txn, &self.record, &self.found)
    }
}

/// The owner's proof, rechecked at the owner tier in `txn`: the acting
/// owner.
fn live_owner_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &RoTxn<'_>,
    refusal: &'static str,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            refusal,
        )));
    }
    Ok(actor)
}

/// Whether a key was found in an entity the owner can delete, not in a row
/// outside the entity tables.
fn is_record_place(place: &str) -> bool {
    matches!(place, "body" | "claim" | "file") || place.starts_with("text:")
}

fn gate_ref(decision: GateDecisionId) -> String {
    format!("gate:{}", decision.to_hex())
}

/// Appends the owner's ruling to the Gate receipt family, in `txn`.
fn append_ruling_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    found: &Located,
    place: &str,
    reason: &'static str,
    revocation: EntityId,
) -> Result<GateDecisionId> {
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "approved".into(),
        reason_codes: vec![reason.into()],
        receipt_reasons: Vec::new(),
        system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
            FOUND_KEY_CONTENT_KIND,
            vec![
                format!("handle:{}", found.handle),
                format!("record:{}", found.record.to_hex()),
                format!("place:{place}"),
                format!("kind:{}", found.key().kind()),
                format!("revocation:{}", revocation.to_hex()),
            ],
        ),
        actor_class: "human".into(),
        actor_ref: Some(actor.to_hex()),
        content_kind: FOUND_KEY_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: found.custody.as_bytes().to_vec(),
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}

/// Drops `custody`'s key from the mark of the file `record` stores.
fn drop_file_key_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    custody: &EntityId,
) -> Result<()> {
    let LiveEntityRow::Live { body, .. } = live_entity_row_in_txn(&vault.store, txn, record)?
    else {
        return Ok(());
    };
    let hash = *blake3::hash(&body).as_bytes();
    crate::secret_custody::masked_files::drop_masked_key_in_txn(&vault.store, txn, &hash, custody)
}

/// Writes `record` again with `value` back where its body holds `handle`.
/// The ruling already stands, so the write door reads the value as no hit.
fn restore_body_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    handle: &str,
    value: &[u8],
) -> Result<()> {
    if !live_entity_row_in_txn(&vault.store, txn, record)?.is_live() {
        return Ok(());
    }
    let Some(raw) = vault.get_raw_in(txn, record)? else {
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("found key record header"))?;
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(());
    };
    let Some(restored) = unmasked_body(body, handle, value)? else {
        return Ok(());
    };
    let learned_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    vault
        .batch_in()
        .put(
            record,
            header.entity_type,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at,
            &restored,
        )
        .apply(txn)
}

/// Writes the text `record` keeps for its field `field` again with `value`
/// back where the mask left `handle`, through the batch door's text op as the
/// lift sweep writes it: the text its live revision staged for idle
/// publication when there is one, else the text it was indexed with (FIX
/// 2649). The ruling already stands, so the write door reads the value as no
/// hit.
fn restore_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    field: &str,
    handle: &str,
    value: &[u8],
) -> Result<()> {
    if !live_entity_row_in_txn(&vault.store, txn, record)?.is_live() {
        return Ok(());
    }
    let mut fields = match entity_revision::staged_live_index_fields(&vault.store, txn, record)? {
        Some(staged) => staged,
        None => INDEX_SOURCE_TEXT
            .get_lenient(&vault.store, txn, record)?
            .unwrap_or_default(),
    };
    let text_form = format!("{HANDLE_TEXT_OPEN}{handle}]");
    let Some((_, text)) = fields
        .iter_mut()
        .find(|(name, text)| name == field && text.contains(&text_form))
    else {
        return Ok(());
    };
    *text = text.replace(&text_form, as_text(value)?);
    crate::store::text_index::deindex_text(&vault.store, txn, record)?;
    let fields = fields
        .iter()
        .map(|(name, text)| (name.as_str(), text.as_str()))
        .collect::<Vec<_>>();
    vault.batch_in().text(record, &fields).apply(txn)
}

/// Writes the claim `record` again with `value` back where the mask left
/// `handle` in its value, evidence or scope, through the sealed
/// owner-restore transition (FIX 11882): a stored claim body rewrites only
/// under that proof. The ruling already stands, so the write door reads
/// the value as no hit. A MACHINE claim whose signed history owns its
/// body refuses: its proof would fail over the restored body and no door
/// re-signs a stored claim, so the ruling does not stand for it yet.
fn restore_claim_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    handle: &str,
    value: &[u8],
) -> Result<()> {
    if !live_entity_row_in_txn(&vault.store, txn, record)?.is_live() {
        return Ok(());
    }
    let Some(raw) = vault.get_raw_in(txn, record)? else {
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("found key record header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(());
    }
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(());
    };
    let prior = crate::claim::decode_claim_body(body, false)?;
    if crate::authority::machine_claim_needs_history(&vault.store, txn, &prior)? {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "a key found in a MACHINE claim cannot take its value back yet: the claim's \
             signed history owns its body, and no door re-signs a stored claim",
        )));
    }
    let text_form = format!("{HANDLE_TEXT_OPEN}{handle}]");
    let mut next = prior;
    let mut changed = false;
    for part in [
        Some(&mut next.value),
        next.evidence.as_mut(),
        next.scope.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        changed |= unmask_value(part, handle, &text_form, value)?;
    }
    if !changed {
        return Ok(());
    }
    let op = crate::batch::BatchOp::Put {
        id: *record,
        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
        occurred: TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        learned_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        row_version: None,
        data: crate::claim::encode_claim_body(&next)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    };
    let transition = crate::batch::VerifiedClaimTransition::after_owner_restore(
        &vault.store,
        txn,
        &op,
        handle,
        value,
    )?;
    crate::batch::apply_ops_with_gate_mode(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![op],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        crate::batch::ApplyOpsGateMode::new(false, true)
            .with_verified_claim_transitions(vec![transition]),
    )
}

/// `body` with `value` back where the mask left `handle`, read as the mask
/// reads a body: JSON, a whole MessagePack value, or text. A span's text
/// form, `[secret sc12]`, and a credential field's whole value, `sc12`, both
/// take it back. `None` when the body holds neither.
fn unmasked_body(body: &[u8], handle: &str, value: &[u8]) -> Result<Option<Vec<u8>>> {
    let text_form = format!("{HANDLE_TEXT_OPEN}{handle}]");
    if let Ok(mut tree) = serde_json::from_slice::<Value>(body) {
        if !unmask_value(&mut tree, handle, &text_form, value)? {
            return Ok(None);
        }
        return serde_json::to_vec(&tree)
            .map(Some)
            .map_err(|_| Error::InvariantViolation("a restored JSON body did not encode"));
    }
    let mut cursor = std::io::Cursor::new(body);
    if let Ok(mut tree) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == body.len() as u64
    {
        if !unmask_value(&mut tree, handle, &text_form, value)? {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(body.len());
        rmpv::encode::write_value(&mut out, &tree)
            .map_err(|_| Error::InvariantViolation("a restored MessagePack body did not encode"))?;
        return Ok(Some(out));
    }
    match std::str::from_utf8(body) {
        Ok(text) if text.contains(&text_form) => {
            Ok(Some(text.replace(&text_form, as_text(value)?).into_bytes()))
        }
        _ => Ok(None),
    }
}

pub(crate) use crate::file_secret_marks::unmask_value;

use crate::file_secret_marks::as_text;
