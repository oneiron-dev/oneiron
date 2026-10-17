//! The owner's four answers to a found key: rotate (the rotate door settles
//! it), delete, grant and not a secret. Each is owner-only, checked at the
//! owner tier in the transaction that acts, and each leaves its receipt on
//! the key.

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use zeroize::{Zeroize, Zeroizing};

use super::{FOUND, FoundKey, FoundKeyAction, FoundKeyCard, FoundKeySettled, FoundKeys};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::memory::{MemoryResult, SafeDeleteReason};
use crate::secret_custody::doors::{
    read_secret_custody_admission_in_txn, read_secret_custody_in_txn,
};
use crate::secret_custody::reveal::{
    not_active, resolve_handle_in_txn, reveal_bound, reveal_connection, unknown,
};
use crate::secret_custody::types::SecretCustodyStatus;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, Vault, live_entity_row_in_txn};

/// Gate reason code: the owner ruled a found key no secret.
pub const FOUND_KEY_REASON_NOT_A_SECRET: &str = "gate.secret.found_key.not_a_secret";

/// The Gate content kind of a found-key ruling.
const FOUND_KEY_CONTENT_KIND: &str = "secret_found_key";

/// How the delete answer removes the record that held a key: a hard delete,
/// whose body is purged and whose redaction receipt is the answer's. Canon
/// names no tier; a record that held a key keeps no shell of it.
const FOUND_KEY_DELETE: SafeDeleteReason = SafeDeleteReason::UserHardDelete;

/// The text form a mask leaves in a span, `[secret sc12]`, before the
/// handle.
const HANDLE_TEXT_OPEN: &str = "[secret ";

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
    /// key the owner ruled no secret.
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
    /// found outside any record (a side row), or one ruled no secret.
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
                for key in found.keys.iter_mut().filter(|key| !key.ruled_no_secret()) {
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
    /// revoked, the record's body gets the value back where the mask left
    /// its handle, or the file's mark drops the key, and a Gate record keeps
    /// the ruling. A portable record's revocation reaches the owner's other
    /// machines as a signed transition.
    ///
    /// Only a key found in a record's body or in a file is ruled here; one in
    /// a claim, a text field alone or a row outside the entity tables keeps
    /// its handle.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's. [`Error::EntityNotFound`] for a handle no notice names.
    /// [`GateError::InvalidConsentBound`] for a key already ruled, a place
    /// that cannot take its value back, or a value that is not text going
    /// back into text. What the record's write door returns.
    pub fn rule_found_key_not_a_secret(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
    ) -> Result<FoundKeySettled> {
        let _ = self.load_install_signing_if_minted();
        let (settled, transition) = self.with_write_txn_grouped(|txn| {
            let actor = live_owner_in_txn(self, owner, txn, "only the vault owner rules on it")?;
            let mut found = Located::find_in_txn(&self.store, txn, handle)?;
            found.refuse_ruled()?;
            let place = found.key().place.clone();
            if place != "body" && place != "file" {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "only a key found in a record's body or a file takes its value back",
                )));
            }
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut rec = read_secret_custody_in_txn(&self.store, txn, &found.custody)?
                .ok_or_else(|| unknown(&found.handle))?;
            let value = Zeroizing::new(std::mem::take(&mut rec.value_bytes));
            let revoked = self.revoke_secret_in_txn(txn, &rec.name, at)?;
            let decision =
                append_ruling_in_txn(self, txn, actor, &found, &place, revoked.receipt_id)?;
            let settled = FoundKeySettled {
                action: FoundKeyAction::NotASecret,
                by: Some(actor),
                at,
                receipt: gate_ref(decision),
                grant_ref: None,
            };
            // The ruling stands before the record is written again.
            found.settle(&self.store, txn, settled.clone())?;
            if place == "file" {
                drop_file_key_in_txn(self, txn, &found.record, &found.custody)?;
            } else {
                restore_body_in_txn(self, txn, &found.record, &found.handle, &value)?;
            }
            let transition = match read_secret_custody_in_txn(&self.store, txn, &found.custody)? {
                Some(mut after) => {
                    let transition = crate::secret_custody::write_custody_transition_in_txn(
                        self,
                        txn,
                        found.custody,
                        &after,
                        at,
                    );
                    after.value_bytes.zeroize();
                    transition?
                }
                None => None,
            };
            Ok((settled, transition))
        })?;
        #[cfg(feature = "sync")]
        if transition.is_some() {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = transition;
        Ok(settled)
    }
}

/// Settles the found key `custody` holds, if a mask found it and the owner
/// has not ruled it no secret: the rotate door's seam.
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
        .find(|key| key.custody == *custody && !key.ruled_no_secret())
    else {
        return Ok(());
    };
    key.settled = Some(settled);
    FOUND.put(store, txn, &origin.record, &found)
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
    if !key.ruled_no_secret() {
        let status = rec.as_ref().map(|rec| rec.status);
        if status == Some(SecretCustodyStatus::Active) {
            actions.extend([FoundKeyAction::Rotate, FoundKeyAction::Grant]);
        }
        if is_record_place(&key.place)
            && live_entity_row_in_txn(&vault.store, txn, record)?.is_live()
        {
            actions.push(FoundKeyAction::Delete);
        }
        if matches!(key.place.as_str(), "body" | "file")
            && status.is_some_and(|status| status != SecretCustodyStatus::Revoked)
        {
            actions.push(FoundKeyAction::NotASecret);
        }
    }
    Ok(FoundKeyCard {
        handle: key.handle.clone(),
        name: rec.map(|rec| rec.name).unwrap_or_default(),
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
    revocation: EntityId,
) -> Result<GateDecisionId> {
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "approved".into(),
        reason_codes: vec![FOUND_KEY_REASON_NOT_A_SECRET.into()],
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

/// [`unmasked_body`] over one decoded value: whether anything changed.
fn unmask_value(tree: &mut Value, handle: &str, text_form: &str, value: &[u8]) -> Result<bool> {
    let restored = match &*tree {
        Value::String(text) => match text.as_str() {
            Some(text) => unmasked_text(text, handle, text_form, value)?,
            None => None,
        },
        Value::Binary(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => unmasked_text(text, handle, text_form, value)?,
            Err(_) => None,
        },
        _ => None,
    };
    if let Some(restored) = restored {
        *tree = restored;
        return Ok(true);
    }
    let mut changed = false;
    match tree {
        Value::Array(items) => {
            for item in items {
                changed |= unmask_value(item, handle, text_form, value)?;
            }
        }
        Value::Map(fields) => {
            for (key, member) in fields.iter_mut() {
                changed |= unmask_value(key, handle, text_form, value)?;
                changed |= unmask_value(member, handle, text_form, value)?;
            }
        }
        _ => {}
    }
    Ok(changed)
}

/// One string of a body with the value back: the whole of it when it is the
/// handle a credential field keeps, each span's text form within it
/// otherwise.
fn unmasked_text(text: &str, handle: &str, text_form: &str, value: &[u8]) -> Result<Option<Value>> {
    if text == handle {
        return Ok(Some(match std::str::from_utf8(value) {
            Ok(value) => Value::from(value),
            Err(_) => Value::Binary(value.to_vec()),
        }));
    }
    if text.contains(text_form) {
        return Ok(Some(Value::from(text.replace(text_form, as_text(value)?))));
    }
    Ok(None)
}

fn as_text(value: &[u8]) -> Result<&str> {
    std::str::from_utf8(value).map_err(|_| {
        Error::Gate(GateError::InvalidConsentBound(
            "the key is not text, so it cannot go back into the record's text",
        ))
    })
}
