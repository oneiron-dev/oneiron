//! What one row's bytes become on their way to another vault.
//!
//! SCOPED-EXPORT-RULE = A (ARCH-0027 :382): "There the serializer zeroes a
//! credential the grant does not admit", and no federation grant admits one.
//! A signed engine row cannot take that rewrite: its proof bytes are public
//! attestation, which the typed rule reads as opaque, and a rewritten body no
//! longer verifies. So the engine's own protocol forms are judged on their
//! content first (EXPORTDOORS-PROOF-SLOTS = A, 12 Nov 03:11):
//!
//! 1. a WORLD_KEY_PAD body the pad codec reads leaves byte-exact, as in the
//!    scoped record door;
//! 2. an AUTHORITY_LOG entry its codec validates leaves byte-exact, unless the
//!    raw scanner finds a credential in its caller-supplied bytes;
//! 3. a machine-signed or machine-history CLAIM, a signed TASK ask companion
//!    and a MESSAGE with provider-signed parts are judged with exactly their
//!    proof slots masked: unchanged, the stored bytes leave byte-exact;
//!    changed, the whole row stays home. A signed body is never rewritten,
//!    and a bearer token is content, never a proof slot;
//! 4. every other row takes the typed rule as built.

use std::io::Cursor;

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::history_store::MachineHistoryKind;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_TASK, ENTITY_TYPE_WORLD_KEY_PAD,
};
use crate::{EntityId, Vault};

/// What one row's bytes become on their way to another vault.
pub(super) enum RowRelease {
    /// The stored bytes, byte-exact.
    Exact,
    /// The typed rule's Nulled body under the row's own header and id.
    Rewritten(Vec<u8>),
    /// Nothing: the row stays home.
    Withheld,
}

/// The release of a row this selector would ship to another vault. A
/// by-reference ASSET is judged by its whole file body, which its carrier
/// lets the receiver fetch, and leaves as its carrier only when that body
/// passes unchanged: the rule never rewrites an ASSET. A row this export
/// cannot read or judge is withheld, not a failed export: one bad row must
/// not fail the whole window closed.
pub(super) fn released_for_other_vault(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> RowRelease {
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return RowRelease::Withheld;
    };
    let Some((prefix, body)) = blob.split_at_checked(ENTITY_METADATA_HEADER_LEN) else {
        return RowRelease::Withheld;
    };
    let kind = header.entity_type;
    if kind == ENTITY_TYPE_ASSET {
        let Ok(row) = vault.materialized_row_in_txn(rtxn, id, blob.to_vec()) else {
            return RowRelease::Withheld;
        };
        return match crate::batch::export::export_released_record(kind, row) {
            Ok(Some(_)) => RowRelease::Exact,
            Ok(None) | Err(_) => RowRelease::Withheld,
        };
    }
    let verdict = match kind {
        ENTITY_TYPE_WORLD_KEY_PAD => oneiron_store::world_pad_codec::decode_pad_body(body)
            .is_ok()
            .then_some(true),
        ENTITY_TYPE_AUTHORITY_LOG => authority_entry_verdict(body),
        ENTITY_TYPE_CLAIM => signed_claim_verdict(prefix, body),
        ENTITY_TYPE_TASK => ask_companion_verdict(vault, rtxn, *id, &header, prefix, body),
        ENTITY_TYPE_MESSAGE => signed_message_verdict(prefix, body),
        _ => None,
    };
    match verdict {
        Some(true) => RowRelease::Exact,
        Some(false) => RowRelease::Withheld,
        None => typed_release(kind, blob),
    }
}

/// The typed rule as built: byte-exact when it changes nothing, else its
/// Nulled body, else withheld.
fn typed_release(kind: u8, blob: &[u8]) -> RowRelease {
    match crate::batch::export::export_released_record(kind, blob.to_vec()) {
        Ok(Some(released)) if released == blob => RowRelease::Exact,
        Ok(Some(released)) => RowRelease::Rewritten(released),
        Ok(None) | Err(_) => RowRelease::Withheld,
    }
}

/// Whether the typed rule and the raw check leave a judging copy (the row's
/// own header around a masked body) exactly as it is. The copy is only
/// judged, never sent.
fn judged_unchanged(kind: u8, prefix: &[u8], masked: &Value) -> bool {
    let mut record = prefix.to_vec();
    if rmpv::encode::write_value(&mut record, masked).is_err() {
        return false;
    }
    matches!(
        crate::batch::export::export_released_record(kind, record.clone()),
        Ok(Some(released)) if released == record
    )
}

/// The whole MessagePack value of `bytes`, with no trailing bytes.
fn read_tree(bytes: &[u8]) -> Option<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    (cursor.position() == bytes.len() as u64).then_some(value)
}

/// The one member at `path` of nested maps; none when a step is missing,
/// is not a map, or names two members.
fn member_mut<'a>(value: &'a mut Value, path: &[&str]) -> Option<&'a mut Value> {
    let Some((name, rest)) = path.split_first() else {
        return Some(value);
    };
    let Value::Map(fields) = value else {
        return None;
    };
    let mut found = None;
    for (key, field) in fields.iter_mut() {
        if key.as_str() == Some(*name) {
            if found.is_some() {
                return None;
            }
            found = Some(field);
        }
    }
    member_mut(found?, rest)
}

/// Members of an authority entry whose bytes the entry codec checks only by
/// length or not at all: attestation evidence, and a machine profile's
/// encryption key and possession proof.
const AUTHORITY_CALLER_BYTES: [&str; 3] = ["evidence", "encryption_key", "machine_proof"];

/// Arm (2). An entry the authority codec refuses takes the typed rule.
fn authority_entry_verdict(body: &[u8]) -> Option<bool> {
    crate::authority::validate_authority_log_entry_body_bytes(body).ok()?;
    let Some(entry) = read_tree(body) else {
        return Some(false);
    };
    Some(authority_caller_bytes_clean(&entry))
}

fn authority_caller_bytes_clean(value: &Value) -> bool {
    match value {
        Value::Map(fields) => fields.iter().all(|(key, field)| {
            let caller_bytes = key
                .as_str()
                .is_some_and(|name| AUTHORITY_CALLER_BYTES.contains(&name));
            let clean = match field {
                Value::Binary(bytes) if caller_bytes => {
                    crate::batch::secret_scan::scan_undecoded_body(bytes).is_none()
                }
                Value::String(text) if caller_bytes => {
                    crate::batch::secret_scan::scan_undecoded_body(text.as_bytes()).is_none()
                }
                _ => true,
            };
            clean && authority_caller_bytes_clean(field)
        }),
        Value::Array(items) => items.iter().all(authority_caller_bytes_clean),
        _ => true,
    }
}

/// Arm (3) for CLAIM. A CLAIM with neither a machine signature nor a
/// machine-history predicate, or one its codec refuses, takes the typed rule.
fn signed_claim_verdict(prefix: &[u8], body: &[u8]) -> Option<bool> {
    let claim = crate::write_envelope::claim_body::decode_claim_body(body, true).ok()?;
    let history = crate::claim::history_store::machine_history_kind(&claim.predicate);
    let machine_signed = claim
        .evidence
        .as_ref()
        .and_then(Value::as_map)
        .is_some_and(|fields| {
            fields
                .iter()
                .any(|(key, _)| key.as_str() == Some("machine_signature"))
        });
    if history.is_none() && !machine_signed {
        return None;
    }
    Some(
        masked_signed_claim(prefix, body, &claim, history)
            .is_some_and(|masked| judged_unchanged(ENTITY_TYPE_CLAIM, prefix, &masked)),
    )
}

/// The CLAIM body with its proof slots masked. A history CLAIM's value is a
/// signed native payload: it must decode, a birth's initial body is judged as
/// a CLAIM of its own, and a handoff's scope must be the outer CLAIM's, which
/// stays judged; then the value is masked. None withholds the row.
fn masked_signed_claim(
    prefix: &[u8],
    body: &[u8],
    claim: &crate::claim::ClaimBody,
    history: Option<MachineHistoryKind>,
) -> Option<Value> {
    let mut masked = read_tree(body)?;
    if let Some(kind) = history {
        let Value::Binary(payload) = &claim.value else {
            return None;
        };
        match kind {
            MachineHistoryKind::Birth => {
                let birth = crate::claim::SignedClaimBirth::decode(payload).ok()?;
                crate::write_envelope::claim_body::decode_claim_body(&birth.initial_body, true)
                    .ok()?;
                let mut initial = read_tree(&birth.initial_body)?;
                mask_machine_proof(&mut initial)?;
                if !judged_unchanged(ENTITY_TYPE_CLAIM, prefix, &initial) {
                    return None;
                }
            }
            // Fixed-width ids, hashes, keys and one scalar delta: no
            // caller content.
            MachineHistoryKind::Transition => {
                crate::claim::transition::decode_machine_claim_transition_event(payload).ok()?;
            }
            MachineHistoryKind::Handoff => {
                let packet = crate::claim::ClaimHistoryHandoff::decode(payload).ok()?;
                if packet.scope
                    != crate::claim::history_store::machine_history_scope_bytes(claim).ok()?
                {
                    return None;
                }
            }
        }
        *member_mut(&mut masked, &["val"])? = Value::Nil;
    }
    mask_machine_proof(&mut masked)?;
    Some(masked)
}

/// Masks a CLAIM's machine signature (a 32-byte key and a 64-byte signature)
/// and its 32-byte authority frontier, the evidence members the write
/// envelope stamps. Every other evidence member stays judged. None when a
/// present slot has another shape.
fn mask_machine_proof(claim: &mut Value) -> Option<()> {
    if let Some(proof) = member_mut(claim, &["evid", "machine_signature"]) {
        let Value::Array(parts) = &*proof else {
            return None;
        };
        let [Value::Binary(key), Value::Binary(signature)] = parts.as_slice() else {
            return None;
        };
        if key.len() != 32 || signature.len() != 64 {
            return None;
        }
        *proof = Value::Nil;
    }
    if let Some(frontier) = member_mut(claim, &["evid", "authority_frontier"]) {
        if !matches!(&*frontier, Value::Binary(hash) if hash.len() == 32) {
            return None;
        }
        *frontier = Value::Nil;
    }
    Some(())
}

/// Arm (3) for TASK: the four ask companions that carry a signature or a
/// digest it binds. The native ask guard reads the stored row first; a row it
/// refuses stays home. A forward intent's `proof.token` is a bearer slip and
/// stays judged, so such an intent never leaves. Every other TASK takes the
/// typed rule.
fn ask_companion_verdict(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
    header: &EntityMetadataHeader,
    prefix: &[u8],
    body: &[u8],
) -> Option<bool> {
    let mut masked = read_tree(body)?;
    let slots: &[&[&str]] = match member_mut(&mut masked, &["subkind"])?.as_str()? {
        "tasks.ask_answer" => &[
            &["link_proof", "signature"],
            &["link_proof", "token_digest"],
        ],
        "tasks.ask_forward_result" => &[&["signature"], &["payload_digest"]],
        "tasks.ask_forward_intent" => &[&["proof", "signature"], &["payload_digest"]],
        "tasks.ask_settlement" => &[&["settlement", "link_result_proof"]],
        _ => return None,
    };
    let occurred = crate::TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    if crate::task_verb::guard_ask_fact_put(
        &vault.store,
        rtxn,
        id,
        occurred,
        header.learned_at,
        body,
    )
    .is_err()
    {
        return Some(false);
    }
    for slot in slots {
        if let Some(value) = member_mut(&mut masked, slot) {
            *value = Value::Nil;
        }
    }
    Some(judged_unchanged(ENTITY_TYPE_TASK, prefix, &masked))
}

/// Arm (3) for MESSAGE: a provider's signature on a text, reasoning or tool
/// call part. A MESSAGE with no such signature takes the typed rule; one
/// with a signature must be a canonical witness body and is judged with
/// exactly those part signatures masked.
fn signed_message_verdict(prefix: &[u8], body: &[u8]) -> Option<bool> {
    let mut masked = read_tree(body)?;
    let Some(Value::Array(parts)) = member_mut(&mut masked, &["parts"]) else {
        return None;
    };
    let mut signed = false;
    for part in parts.iter_mut() {
        let signed_kind = member_mut(part, &["kind"])
            .and_then(|kind| kind.as_str())
            .is_some_and(|kind| matches!(kind, "text" | "reasoning" | "tool_call"));
        if !signed_kind {
            continue;
        }
        if let Some(signature) = member_mut(part, &["signature"])
            && !signature.is_nil()
        {
            *signature = Value::Nil;
            signed = true;
        }
    }
    if !signed {
        return None;
    }
    if crate::store::witness_message_body::validate_canonical_witness_message_body(body).is_err() {
        return Some(false);
    }
    Some(judged_unchanged(ENTITY_TYPE_MESSAGE, prefix, &masked))
}
