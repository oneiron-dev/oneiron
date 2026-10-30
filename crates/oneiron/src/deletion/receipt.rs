use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
#[cfg(feature = "sync")]
use crate::error::SyncError;
use crate::error::{Error, Result};

use super::erase::{take_corrupt_capture_in_txn, take_staged_sweep_refs_in_txn};
use super::receipt_final::finish_redaction_erase_in_txn;
use super::sweep_queue::{HardEraseSweepExtras, hard_erase_sweep_deadline_at};
use super::tombstone::DeleteReason;

// The audited corrupt-CLAIM classification's repair event and failure record (FIX 7800).
mod capture;

pub(crate) use capture::{
    CAPTURE_FAILED, CaptureFailure, encode_corrupt_claim_repair_event,
    is_corrupt_claim_repair_event,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RedactionScope {
    pub entity_ids: Vec<String>,
    pub revision_ids: Vec<String>,
}

impl RedactionScope {
    pub(crate) fn entity(entity_id: &EntityId) -> Self {
        Self {
            entity_ids: vec![entity_id.to_hex()],
            revision_ids: Vec::new(),
        }
    }
}

/// The pinned REDACTION_AUDIT body shape (`rmp_serde::to_vec_named`, field
/// order = the pinned `RECEIPT_BODY_KEYS` order). `Deserialize` exists for
/// the ONE-1087 sweep executor, which reads a receipt to append its linked
/// completion row (OF-470, ARCH-0038 step 10), and for the erase's overall
/// final row (FIX 5844); a stored receipt never changes. One shape, three
/// phases: the erase's initial receipt has neither completion time, its
/// sweep row has `sweep_complete_at` alone, and its final row has
/// `erase_complete_at`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RedactionAuditReceipt {
    pub(crate) request_id: String,
    pub(crate) scope: RedactionScope,
    pub(crate) reason: String,
    pub(crate) requested_at: u64,
    pub(crate) soft_complete_at: u64,
    pub(crate) hard_purge_complete_at: u64,
    pub(crate) sweep_queued_at: Option<u64>,
    pub(crate) sweep_deadline_at: Option<u64>,
    pub(crate) sweep_complete_at: Option<u64>,
    pub(crate) affected_revision_ids: Vec<String>,
    /// Optional room-specific authority, never content from the erased record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) actor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) room_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) room_role: Option<crate::conversation::RoomRole>,
    /// When the erase completed overall, on its final row alone: its sweep,
    /// if it queued one, and every custody retirement it binds had finished
    /// (FIX 5844, C-ERASE-FINAL).
    pub(crate) erase_complete_at: Option<u64>,
    /// The custody retirements this erase owes, each by its value-free name
    /// (kind tag, item id, generation), fixed when the erase ran. Empty is
    /// the explicit `not required`: nothing it erased was in custody here.
    pub(crate) custody_retirements: Vec<String>,
    /// Each record whose capture took the audited corrupt-CLAIM exception, with
    /// the repair event that classified it, ascending by id (FIX 7800); absent
    /// when none did. Fixed when the erase ran, as its linked rows copy it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) capture_failures: Vec<CaptureFailure>,
    pub(crate) verification: BTreeMap<String, String>,
}

impl RedactionAuditReceipt {
    /// Whether this is an erase's initial receipt, not a row appended to it
    /// later (its sweep row or its overall final row).
    pub(crate) fn is_initial(&self) -> bool {
        self.sweep_complete_at.is_none() && self.erase_complete_at.is_none()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RedactionReceiptInput {
    pub actor_principal: Option<EntityId>,
    pub room_authority: Option<(EntityId, crate::conversation::RoomRole)>,
    pub request_id: String,
    pub scope: RedactionScope,
    pub reason: DeleteReason,
    pub requested_at: u64,
    pub soft_complete_at: u64,
    pub hard_purge_complete_at: u64,
    pub sweep_queued_at: Option<u64>,
}

// ─── Receipt origin attestation (ONE-1140, OD-6) ─────────────────────────────
//
// The receipt body's `verification` map — the M4-pinned extension point
// ("verification must be empty UNTIL the audit-chain proof schema is
// pinned") — now carries EXACTLY four attestation entries (this versions
// the M4 pin; values are lowercase-hex strings, BTreeMap iteration = sorted
// keys = deterministic encoding):
//
//   "att_client" → str(16)  client_id hex (BE nibble order, `{:016x}`)
//   "att_pk"     → str(64)  Ed25519 verifying key hex
//   "att_sig"    → str(128) Ed25519 signature hex
//   "att_v"      → str(1)   "1"
//
// Signature transcript (byte-exact):
//   msg = RECEIPT_ATT_DOMAIN || entity_id:16
//         || envelope_header:25 ([type:1][occurred_start:8 BE]
//            [occurred_end:8 BE][learned_at:8 BE], exactly the stored bytes)
//         || body_msgpack_with_verification_EMPTY
//
// The signer encodes with `verification = {}` (those bytes ARE the
// transcript tail), signs, then re-encodes with the four att_ entries. The
// verifier reconstructs the tail by splicing: `verification` is required to
// be the FINAL map entry in bytes (rmp_serde named-struct order guarantees
// it for the legitimate writer; the validator enforces it), so
// `body[..verification_value_offset] || 0x80` reproduces the signed bytes
// — same top-level map header both ways, no re-serialization
// canonicalization trap.

/// Attestation transcript domain separator (OD-6 literal).
pub(crate) const RECEIPT_ATT_DOMAIN: &[u8] = b"oneiron/receipt-att/v1";
pub(super) const ATT_KEY_CLIENT: &str = "att_client";
pub(super) const ATT_KEY_PK: &str = "att_pk";
pub(super) const ATT_KEY_SIG: &str = "att_sig";
pub(super) const ATT_KEY_V: &str = "att_v";
/// Attestation schema version literal carried in `att_v`.
pub(super) const ATT_VERSION: &str = "1";
/// MessagePack fixmap(0) — the empty `verification` the transcript tail
/// carries in place of the four att_ entries.
pub(crate) const ATT_EMPTY_MAP_BYTE: u8 = 0x80;

/// The pinned 25 B REDACTION_AUDIT envelope header: receipts are point
/// events (`occurred_start == occurred_end == learned_at`), all three
/// timestamps u64 BE. Shared by the receipt writer and the attestation
/// transcript so the signed header bytes are EXACTLY the stored bytes.
pub(crate) fn receipt_envelope_header(learned_at: u64) -> [u8; 25] {
    let mut header = [0u8; 25];
    header[0] = crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    header[1..9].copy_from_slice(&learned_at.to_be_bytes());
    header[9..17].copy_from_slice(&learned_at.to_be_bytes());
    header[17..25].copy_from_slice(&learned_at.to_be_bytes());
    header
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Encodes an erase's initial REDACTION_AUDIT receipt body, signed by this
/// device (OD-6), binding `custody_retirements`, the names of the custody
/// retirements the erase owes (FIX 5844; empty: `not required`), and
/// `capture_failures`, its records that took the audited corrupt-CLAIM
/// exception (FIX 7800; empty for every other erase).
///
/// `receipt_id` and `input.hard_purge_complete_at` (the envelope
/// `learned_at`) are bound into the transcript so a valid receipt cannot be
/// transplanted under another entity id or a shifted envelope.
pub(crate) fn encode_redaction_audit_receipt(
    input: RedactionReceiptInput,
    custody_retirements: Vec<String>,
    capture_failures: Vec<CaptureFailure>,
    receipt_id: &EntityId,
    identity: &crate::identity::DeviceIdentity,
) -> Result<Vec<u8>> {
    let envelope_learned_at = input.hard_purge_complete_at;
    let receipt = RedactionAuditReceipt {
        request_id: input.request_id,
        scope: input.scope,
        reason: input.reason.as_str().to_owned(),
        requested_at: input.requested_at,
        soft_complete_at: input.soft_complete_at,
        hard_purge_complete_at: input.hard_purge_complete_at,
        sweep_queued_at: input.sweep_queued_at,
        sweep_deadline_at: input
            .sweep_queued_at
            .map(|_| hard_erase_sweep_deadline_at(input.requested_at)),
        sweep_complete_at: None,
        affected_revision_ids: Vec::new(),
        actor_ref: input
            .room_authority
            .and(input.actor_principal)
            .map(|id| id.to_hex()),
        room_ref: input.room_authority.map(|(room, _)| room.to_hex()),
        room_role: input.room_authority.map(|(_, role)| role),
        erase_complete_at: None,
        custody_retirements,
        capture_failures,
        verification: BTreeMap::new(),
    };
    sign_redaction_audit_receipt(receipt, receipt_id, envelope_learned_at, identity)
}

/// Signs `receipt` as the body of entity `receipt_id`, whose point-event
/// envelope is stamped `envelope_learned_at`, and encodes it (OD-6). Any
/// `verification` the receipt carries is replaced: the transcript tail is
/// the body with `verification` EMPTY, then the four att_ entries go in.
pub(super) fn sign_redaction_audit_receipt(
    mut receipt: RedactionAuditReceipt,
    receipt_id: &EntityId,
    envelope_learned_at: u64,
    identity: &crate::identity::DeviceIdentity,
) -> Result<Vec<u8>> {
    receipt.verification.clear();
    // Transcript tail: the body bytes with verification EMPTY.
    let body_unsigned = rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))?;
    receipt.verification =
        receipt_attestation(&body_unsigned, receipt_id, envelope_learned_at, identity);
    rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))
}

/// The four att_ entries (OD-6) over `body_unsigned`, a REDACTION_AUDIT body
/// encoded with `verification` EMPTY, for entity `receipt_id` whose
/// point-event envelope is stamped `envelope_learned_at`. Shared by the erase
/// receipt rows and the corrupt-CLAIM repair event, one transcript for both.
fn receipt_attestation(
    body_unsigned: &[u8],
    receipt_id: &EntityId,
    envelope_learned_at: u64,
    identity: &crate::identity::DeviceIdentity,
) -> BTreeMap<String, String> {
    use ed25519_dalek::Signer;

    let header = receipt_envelope_header(envelope_learned_at);
    let mut msg =
        Vec::with_capacity(RECEIPT_ATT_DOMAIN.len() + 16 + header.len() + body_unsigned.len());
    msg.extend_from_slice(RECEIPT_ATT_DOMAIN);
    msg.extend_from_slice(receipt_id.as_bytes());
    msg.extend_from_slice(&header);
    msg.extend_from_slice(body_unsigned);
    let signature = identity.signing_key.sign(&msg);

    let client = format!("{:016x}", identity.client_id);
    let public_key = hex_lower(&identity.signing_key.verifying_key().to_bytes());
    BTreeMap::from([
        (ATT_KEY_CLIENT.to_owned(), client),
        (ATT_KEY_PK.to_owned(), public_key),
        (ATT_KEY_SIG.to_owned(), hex_lower(&signature.to_bytes())),
        (ATT_KEY_V.to_owned(), ATT_VERSION.to_owned()),
    ])
}

/// Decodes a REDACTION_AUDIT receipt BODY (post-envelope bytes).
pub(crate) fn decode_redaction_audit_receipt(body: &[u8]) -> Result<RedactionAuditReceipt> {
    rmp_serde::from_slice(body).map_err(|_| Error::CorruptedIndex("redaction audit receipt body"))
}

fn hex_decode_lower(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !super::receipt_grammar::is_lower_hex(s) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The attestation fields of a validated receipt body plus the byte offset
/// of the `verification` VALUE — the splice point for transcript
/// reconstruction (OD-6).
pub(crate) struct ReceiptAttestationParts {
    pub(crate) client_id: u64,
    pub(crate) pubkey: [u8; 32],
    pub(crate) signature: [u8; 64],
    pub(crate) verification_value_offset: usize,
}

/// Reads a MessagePack map header (fixmap / map16 / map32) off the cursor.
/// The only low-level decode this module hand-rolls: rmpv reads whole
/// values, and the verifier needs the byte OFFSET of the final entry's
/// value, so the top-level header + per-entry walk track positions.
fn read_msgpack_map_len(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> std::result::Result<u64, AttestationSpliceFailure> {
    use std::io::Read;
    let mut first = [0u8; 1];
    cursor
        .read_exact(&mut first)
        .map_err(|_| AttestationSpliceFailure::NotMessagePack)?;
    match first[0] {
        b @ 0x80..=0x8f => Ok(u64::from(b & 0x0f)),
        0xde => {
            let mut len = [0u8; 2];
            cursor
                .read_exact(&mut len)
                .map_err(|_| AttestationSpliceFailure::NotMessagePack)?;
            Ok(u64::from(u16::from_be_bytes(len)))
        }
        0xdf => {
            let mut len = [0u8; 4];
            cursor
                .read_exact(&mut len)
                .map_err(|_| AttestationSpliceFailure::NotMessagePack)?;
            Ok(u64::from(u32::from_be_bytes(len)))
        }
        _ => Err(AttestationSpliceFailure::NotStringKeyedMap),
    }
}

/// Why the shared attestation splice failed. The sync wrapper maps each to
/// the `InvalidRedactionReceiptBody` message `receipt_attestation_parts`
/// returns today, so the sync path behaves exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttestationSpliceFailure {
    /// The body is not valid MessagePack.
    NotMessagePack,
    /// The body is not a string-keyed MessagePack map.
    NotStringKeyedMap,
    /// The attestation fields failed re-parse.
    AttestationReparse,
}

#[cfg(feature = "sync")]
impl AttestationSpliceFailure {
    fn error(self) -> Error {
        Error::Sync(SyncError::InvalidRedactionReceiptBody(match self {
            Self::NotMessagePack => "body is not valid MessagePack",
            Self::NotStringKeyedMap => "body must be a string-keyed MessagePack map",
            Self::AttestationReparse => "attestation fields failed re-parse",
        }))
    }
}

/// Cursor-parses a receipt body (already structurally validated by
/// [`super::receipt_grammar::validate_redaction_receipt_body`]) and extracts the attestation
/// fields plus the verification-value byte offset. The transcript tail is
/// then `body[..verification_value_offset] || ATT_EMPTY_MAP_BYTE` — sound
/// because the validator pinned `verification` as the FINAL entry in bytes
/// with no trailing bytes; a non-canonical re-encoding simply fails the
/// signature (fail closed), never a false accept.
fn receipt_attestation_splice_inner(
    body: &[u8],
) -> std::result::Result<ReceiptAttestationParts, AttestationSpliceFailure> {
    const MALFORMED: AttestationSpliceFailure = AttestationSpliceFailure::AttestationReparse;

    let mut cursor = std::io::Cursor::new(body);
    let entry_count = read_msgpack_map_len(&mut cursor)?;
    let mut parts: Option<ReceiptAttestationParts> = None;
    for _ in 0..entry_count {
        let key = rmpv::decode::read_value(&mut cursor).map_err(|_| MALFORMED)?;
        let is_verification = key.as_str() == Some("verification");
        let value_offset = usize::try_from(cursor.position()).map_err(|_| MALFORMED)?;
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| MALFORMED)?;
        if !is_verification {
            continue;
        }
        let rmpv::Value::Map(fields) = value else {
            return Err(MALFORMED);
        };
        let mut client_id = None;
        let mut pubkey = None;
        let mut signature = None;
        for (att_key, att_value) in &fields {
            let (Some(att_key), Some(att_value)) = (att_key.as_str(), att_value.as_str()) else {
                return Err(MALFORMED);
            };
            match att_key {
                ATT_KEY_CLIENT => {
                    client_id = Some(u64::from_str_radix(att_value, 16).map_err(|_| MALFORMED)?);
                }
                ATT_KEY_PK => {
                    let bytes: [u8; 32] = hex_decode_lower(att_value)
                        .ok_or(MALFORMED)?
                        .try_into()
                        .map_err(|_| MALFORMED)?;
                    pubkey = Some(bytes);
                }
                ATT_KEY_SIG => {
                    let bytes: [u8; 64] = hex_decode_lower(att_value)
                        .ok_or(MALFORMED)?
                        .try_into()
                        .map_err(|_| MALFORMED)?;
                    signature = Some(bytes);
                }
                _ => {}
            }
        }
        parts = Some(ReceiptAttestationParts {
            client_id: client_id.ok_or(MALFORMED)?,
            pubkey: pubkey.ok_or(MALFORMED)?,
            signature: signature.ok_or(MALFORMED)?,
            verification_value_offset: value_offset,
        });
    }
    if cursor.position() != body.len() as u64 {
        return Err(MALFORMED);
    }
    parts.ok_or(MALFORMED)
}

/// The shared attestation splice for verifiers without the sync feature:
/// `None` on any parse failure, which the caller reads as not attested. The
/// same tail splice the sync lease path verifies over the stored bytes.
pub(crate) fn receipt_attestation_splice(body: &[u8]) -> Option<ReceiptAttestationParts> {
    receipt_attestation_splice_inner(body).ok()
}

/// The shared attestation splice for the sync lease path, with the
/// `SyncError`s it returns today.
#[cfg(feature = "sync")]
pub(crate) fn receipt_attestation_parts(body: &[u8]) -> Result<ReceiptAttestationParts> {
    receipt_attestation_splice_inner(body).map_err(AttestationSpliceFailure::error)
}

impl Vault {
    /// Writes a REDACTION_AUDIT receipt as a normal entity-envelope record
    /// (contracts.ts `redactionAuditReceipt.storage`), maintaining the same
    /// index footprint `apply_put` gives every other envelope write. The
    /// receipt is a point event (`occurred_start == occurred_end ==
    /// learned_at`), so per the `apply_put` convention it gets a
    /// `temporal_occurred_start` row but NO `temporal_occurred_end` row and
    /// no `temporal_long_intervals` row. Maintenance kinds carry no short ID.
    fn put_redaction_audit_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        crate::off_record::FloorWrites::new(&self.store)
            .append_redaction_audit(wtxn, receipt_id, learned_at, body)
    }

    pub(super) fn write_redaction_receipt_and_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        mut input: RedactionReceiptInput,
        mut sweep_extras: HardEraseSweepExtras,
    ) -> Result<Vec<u8>> {
        let mut ids = std::collections::BTreeSet::new();
        for hex in &input.scope.entity_ids {
            let holder = EntityId::from_hex(hex)?;
            if input.sweep_queued_at.is_some() {
                take_staged_sweep_refs_in_txn(self, wtxn, &holder, &mut sweep_extras)?;
            }
            ids.insert(holder);
            ids.extend(crate::skill_hub::source_carriers_for_holder_in_txn(
                &self.store,
                wtxn,
                &holder,
            )?);
            ids.extend(crate::agent_def::birth_carriers_for_erased_entity_in_txn(
                &self.store,
                wtxn,
                &holder,
            )?);
            ids.extend(crate::receipt::receipt_archives_for_holder(
                &self.store,
                wtxn,
                &holder,
            )?);
            // The cloud registration slots an owner's erase took (G7).
            ids.extend(crate::secret_custody::cloud_registration_erased_with(
                &holder,
            ));
        }
        input.scope.entity_ids = ids.iter().map(EntityId::to_hex).collect();
        // A classified corrupt CLAIM this erase took the audited exception for
        // leaves its classification here, as `capture_failed` on the receipt and
        // the queued sweep, in the commit that writes both (FIX 7800).
        if input.sweep_queued_at.is_some() {
            for id in &ids {
                take_corrupt_capture_in_txn(self, wtxn, id, &mut sweep_extras)?;
            }
        }
        let failures = &mut sweep_extras.capture_failures;
        failures.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
        failures.dedup_by(|left, right| left.entity_id == right.entity_id);
        let capture_failures = failures.clone();
        // This erase's own custody retirements, everything it retires staged
        // by now in this transaction, bound by name on its receipt and never
        // changed (FIX 5844). Missing proof later reads as pending.
        let erased: Vec<EntityId> = ids.into_iter().collect();
        // An erase reaches the archive copies kept for removed Owners (FIX-LIST 2241).
        self.scrub_removal_exports_in_txn(wtxn, &erased)?;
        let custody_retirements = self.store.erase_custody_retirements_in_txn(wtxn, &erased)?;
        let sweep_key = if let Some(queued_at) = input.sweep_queued_at {
            self.enqueue_hard_erase_sweep_in_txn(
                wtxn,
                input.scope.clone(),
                sweep_extras,
                queued_at,
                input.requested_at,
            )?
        } else {
            Vec::new()
        };

        // ONE-1140 (OD-2/OD-6): every receipt is signed at mint. The device
        // key is the one the delete door loaded before its first txn (P6c);
        // the client id is minted in THIS txn when missing — all receipt-mint
        // paths funnel through here, so this is the single in-txn hook.
        let identity = crate::identity::ensure_device_identity_in_txn(self, wtxn)?;
        let hard_purge_complete_at = input.hard_purge_complete_at;
        for entity in &input.scope.entity_ids {
            crate::ports::audit_mutation_in_txn(
                &self.store,
                wtxn,
                crate::ports::MutationAudit {
                    entity: EntityId::from_hex(entity)?,
                    op: crate::ports::ChangeOp::Forget,
                    actor_principal: input.actor_principal,
                    occurred_at: input.requested_at,
                    input: input.request_id.as_bytes(),
                    reason: Some(input.reason.as_str()),
                },
            )?;
        }
        let body = encode_redaction_audit_receipt(
            input,
            custody_retirements,
            capture_failures,
            receipt_id,
            &identity,
        )?;
        self.put_redaction_audit_receipt_in_txn(wtxn, receipt_id, hard_purge_complete_at, &body)?;
        // An erase that queued no sweep and owes no custody retirement is
        // complete now: its final row lands in this transaction. Any other
        // gets it once the last of those finishes (FIX 5844).
        let receipt = decode_redaction_audit_receipt(&body)?;
        finish_redaction_erase_in_txn(self, wtxn, receipt_id, &receipt, hard_purge_complete_at)?;
        Ok(sweep_key)
    }

    /// Records the privacy erase of the thread audience edit `edit` in the
    /// write that rewrote it in place (FIX 10234): a content-free
    /// REDACTION_AUDIT receipt naming the edit, with no hard-erase sweep, as
    /// the edit stays live and made by no one. Where this vault keeps sync
    /// windows, the erasure sweep is owed a compaction of the window that
    /// carries the edit's earlier revisions, and the receipt completes when
    /// that settles (`sweep::owed`); without them no window carries it, and
    /// the receipt completes now. The device key must already be on the
    /// handle (P6c).
    pub(crate) fn record_audience_edit_erase_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        edit: &EntityId,
        actor_principal: Option<EntityId>,
        reason: DeleteReason,
        requested_at: u64,
    ) -> Result<super::DeleteEntityOutcome> {
        let receipt_id = self.store.clock.entity_id()?;
        let now = self.store.clock.now_recorded_at();
        #[cfg(feature = "sync")]
        let window = {
            let raw = self.get_raw_in(wtxn, edit)?.ok_or(Error::EntityNotFound)?;
            crate::sync::residence::residence_window_for_blob(&raw)?
        };
        let input = RedactionReceiptInput {
            actor_principal,
            room_authority: None,
            request_id: uuid::Uuid::from_bytes(self.store.clock.ulid()?).to_string(),
            scope: RedactionScope::entity(edit),
            reason,
            requested_at,
            soft_complete_at: now,
            hard_purge_complete_at: now,
            sweep_queued_at: cfg!(feature = "sync").then_some(now),
        };
        let identity = crate::identity::ensure_device_identity_in_txn(self, wtxn)?;
        let body =
            encode_redaction_audit_receipt(input, Vec::new(), Vec::new(), &receipt_id, &identity)?;
        self.put_redaction_audit_receipt_in_txn(wtxn, &receipt_id, now, &body)?;
        #[cfg(feature = "sync")]
        let sweep_key = crate::sweep::owed::owe_window_compaction_for_receipt_in_txn(
            self,
            wtxn,
            &window,
            &receipt_id,
        )?;
        #[cfg(not(feature = "sync"))]
        let sweep_key = {
            let receipt = decode_redaction_audit_receipt(&body)?;
            finish_redaction_erase_in_txn(self, wtxn, &receipt_id, &receipt, now)?;
            Vec::new()
        };
        Ok(super::DeleteEntityOutcome {
            existed: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
            turn_program_details: Vec::new(),
        })
    }
}
