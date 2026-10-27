//! ORCB v1: schema-only dictionary and per-claim hot-value AEAD, keyed by the
//! claim's typed custody entry (`key_custody`, kind `ClaimDecision`).
//!
//! `[ORCB | 1 | claim_id:16 | decision_id:16 | nonce:12 | AES-256-GCM(
//! zstd-dict(MessagePack(record)), AAD=header)]`; a rotated generation `g`
//! is version 2 with `g` (u64be) after the nonce, inside the AAD. A
//! claim-free policy row (FIX 7806) is version 3, sealed in the same custody
//! under [`POLICY_PARTITION`] where a claim's id would stand, generation 0:
//! it names no claim, so no claim's erase or retirement reads it as one of
//! that claim's rows. The dictionary consists only of fixed field markers and
//! closed enum tokens; no live value can train it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::store::key_custody::{CustodyKind, CustodySubject, LocalCustody};

use super::ledger::{decode_gate_decision, encode_gate_decision};
use super::types::{GateDecisionId, GateDecisionRecord};

const MAGIC: &[u8; 4] = b"ORCB";
const VERSION: u8 = 1;
const ROTATED_VERSION: u8 = 2;
const POLICY_VERSION: u8 = 3;
/// The custody item claim-free policy rows are sealed under: a fixed id in
/// the `ClaimDecision` kind's item space, which no claim's random id is.
const POLICY_PARTITION: [u8; 16] = *b"policy.receipts\0";
const HEADER_LEN: usize = 4 + 1 + 16 + 16 + 12;
const ROTATED_HEADER_LEN: usize = HEADER_LEN + 8;
const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;

// RAW-CONTENT zstd dictionary (no live training or adaptive state). Every
// token is a schema field name or a closed vocabulary value. Do not add a
// sample taken from a vault, even in a test fixture or build script.
const SYNTHETIC_DICTIONARY: &[u8] = b"version decision_id created_at outcome reason_codes receipt_reasons system_notices actor_class actor_ref content_kind policy_manifest_version claim_id grant_ref diff_handle read_frontier_hash redacted_at notice_type channel voice audience body row_ref setting_change_offer policy_plane policy_version docs_url allow deny hold owner_policy hosted_legal gate.allow gate.deny gate.hold";

pub(super) fn corrupt() -> Error {
    CustodyKind::ClaimDecision.corrupt()
}

/// A claim's key partition in `custody`: kind `ClaimDecision`, item the claim
/// id. Keys sit beside the restorable vault root, never in the LMDB image
/// (`key_custody`).
pub(super) fn claim_subject(custody: LocalCustody<'_>, claim: &[u8; 16]) -> Result<CustodySubject> {
    custody.binding().subject(CustodyKind::ClaimDecision, claim)
}

pub(super) fn encode_hot(
    custody: LocalCustody<'_>,
    record: &GateDecisionRecord,
) -> Result<Vec<u8>> {
    let claim_id = record.claim_id.ok_or_else(corrupt)?;
    let generation = custody.first_unretired(&claim_subject(custody, &claim_id)?)?;
    encode_hot_at(custody, record, generation)
}

/// Encrypts under one named generation. An erase uses this to move a receipt
/// it must keep readable onto the generation after the one it retires.
pub(super) fn encode_hot_at(
    custody: LocalCustody<'_>,
    record: &GateDecisionRecord,
    generation: u64,
) -> Result<Vec<u8>> {
    let claim_id = record.claim_id.ok_or_else(corrupt)?;
    let version = if generation == 0 {
        VERSION
    } else {
        ROTATED_VERSION
    };
    seal(custody, record, claim_id, version, generation)
}

/// Seals a claim-free policy row under [`POLICY_PARTITION`] (FIX 7806).
pub(super) fn encode_policy(
    custody: LocalCustody<'_>,
    record: &GateDecisionRecord,
) -> Result<Vec<u8>> {
    if record.claim_id.is_some() {
        return Err(corrupt());
    }
    seal(custody, record, POLICY_PARTITION, POLICY_VERSION, 0)
}

/// `record` sealed under custody item `item` at `generation`, with header
/// `version`.
fn seal(
    custody: LocalCustody<'_>,
    record: &GateDecisionRecord,
    item: [u8; 16],
    version: u8,
    generation: u64,
) -> Result<Vec<u8>> {
    // The first sealed append publishes and syncs the key before LMDB may
    // commit ciphertext under it.
    let key = custody.get_or_create(&claim_subject(custody, &item)?.at(generation))?;
    let plain = encode_gate_decision(record)?;
    if plain.len() > MAX_PLAINTEXT {
        return Err(Error::InvariantViolation("gate decision ORCB size"));
    }
    let mut compressor = zstd::bulk::Compressor::with_dictionary(3, SYNTHETIC_DICTIONARY)
        .map_err(|_| Error::InvariantViolation("gate decision ORCB compress"))?;
    let compressed = compressor
        .compress(&plain)
        .map_err(|_| Error::InvariantViolation("gate decision ORCB compress"))?;
    let mut header = Vec::with_capacity(ROTATED_HEADER_LEN + compressed.len() + 16);
    header.extend_from_slice(MAGIC);
    header.push(version);
    header.extend_from_slice(&item);
    header.extend_from_slice(&record.decision_id.as_bytes());
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    header.extend_from_slice(&nonce);
    if version == ROTATED_VERSION {
        header.extend_from_slice(&generation.to_be_bytes());
    }
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| corrupt())?;
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &compressed,
                aad: &header,
            },
        )
        .map_err(|_| corrupt())?;
    header.extend_from_slice(&encrypted);
    Ok(header)
}

pub(super) fn decode_hot(
    custody: LocalCustody<'_>,
    decision_id: GateDecisionId,
    raw: &[u8],
) -> Result<GateDecisionRecord> {
    if !raw.starts_with(MAGIC) || raw.len() < HEADER_LEN + 16 {
        return Err(corrupt());
    }
    let (generation, header_len) = match raw[4] {
        VERSION | POLICY_VERSION => (0, HEADER_LEN),
        ROTATED_VERSION if raw.len() >= ROTATED_HEADER_LEN + 16 => {
            let generation = u64::from_be_bytes(
                raw[HEADER_LEN..ROTATED_HEADER_LEN]
                    .try_into()
                    .map_err(|_| corrupt())?,
            );
            if generation == 0 {
                return Err(corrupt());
            }
            (generation, ROTATED_HEADER_LEN)
        }
        _ => return Err(corrupt()),
    };
    let item: [u8; 16] = raw[5..21].try_into().map_err(|_| corrupt())?;
    if raw[21..37] != decision_id.as_bytes() {
        return Err(corrupt());
    }
    // A policy row names the policy partition and no claim; any other names
    // the claim it is sealed to.
    let policy = raw[4] == POLICY_VERSION;
    if policy && item != POLICY_PARTITION {
        return Err(corrupt());
    }
    let key = custody.read(&claim_subject(custody, &item)?.at(generation))?;
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| corrupt())?;
    let nonce: [u8; 12] = raw[37..49].try_into().map_err(|_| corrupt())?;
    let compressed = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &raw[header_len..],
                aad: &raw[..header_len],
            },
        )
        .map_err(|_| corrupt())?;
    let mut decompressor =
        zstd::bulk::Decompressor::with_dictionary(SYNTHETIC_DICTIONARY).map_err(|_| corrupt())?;
    let plain = decompressor
        .decompress(&compressed, MAX_PLAINTEXT)
        .map_err(|_| corrupt())?;
    let record = decode_gate_decision(&plain)?;
    let sealed_to = (!policy).then_some(item);
    if record.claim_id != sealed_to || record.decision_id != decision_id {
        return Err(corrupt());
    }
    Ok(record)
}

/// Whether the key an ORCB header names is retired in `custody`. No custody
/// retires nothing.
pub(super) fn raw_key_retired(custody: Option<LocalCustody<'_>>, raw: &[u8]) -> Result<bool> {
    match (custody, raw_claim_generation(raw)) {
        (Some(custody), Some((claim, generation))) => {
            custody.retired(&claim_subject(custody, &claim)?.at(generation))
        }
        _ => Ok(false),
    }
}

/// The claim and key generation an ORCB header names, read without a key;
/// `None` for a policy row, which names no claim.
pub(super) fn raw_claim_generation(raw: &[u8]) -> Option<([u8; 16], u64)> {
    if !is_orcb(raw) || raw.len() < HEADER_LEN + 16 {
        return None;
    }
    let claim: [u8; 16] = raw[5..21].try_into().ok()?;
    let generation = match raw[4] {
        VERSION => 0,
        ROTATED_VERSION if raw.len() >= ROTATED_HEADER_LEN + 16 => {
            u64::from_be_bytes(raw[HEADER_LEN..ROTATED_HEADER_LEN].try_into().ok()?)
        }
        _ => return None,
    };
    Some((claim, generation))
}

pub(super) fn is_orcb(raw: &[u8]) -> bool {
    raw.starts_with(MAGIC)
}

/// Whether `raw` is a claim-free policy row sealed under the policy
/// partition (FIX 7806).
pub(super) fn is_policy_sealed(raw: &[u8]) -> bool {
    is_orcb(raw) && raw.get(4) == Some(&POLICY_VERSION)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::SYNTHETIC_DICTIONARY;

    #[test]
    fn orcb_v1_dictionary_is_pinned_to_schema_only_tokens() {
        // Changing these bytes without changing the ORCB version silently
        // strands encrypted rows. This fingerprint pins the audited synthetic
        // field/enum corpus; it is not a live-record training fixture.
        let digest = Sha256::digest(SYNTHETIC_DICTIONARY);
        assert_eq!(
            format!("{digest:x}"),
            "0a4fd8b6e54aa65fca3f3ef2a50042e291ee3b00dd7a5bfe9d4faad824b68582"
        );
    }
}
