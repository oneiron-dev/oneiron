//! The protected input of an active custody change (WILL L04 row 04): what a
//! register, rotate or bind hands its holder, sealed to the holder's
//! encryption key alone.
//!
//! A register's input is the whole record, metadata and value, framed with
//! the text of the manifest its recorder resolved it from, when there is one
//! (CALLS CUSTODY_MANIFEST_RECHECK); a rotate's is the new value; a bind's
//! rewrap carries the record's new bindings (CALLS CUSTODY_BIND_TRAVEL). A
//! rewrap that only seals again carries none. The envelope's key id binds
//! the vault, the secret's id, the change, the generation it approves, the
//! custody revision the owner saw, the holder and every permit, so an input
//! never opens as another change's.
//! The request names only the digest of its ciphertext, never a hash of the
//! value. A door that is the holder executes from what it holds in the
//! request's own commit and keeps no input; any other door keeps the input
//! to relay beside the custody transitions, under its digest, with the
//! request it is for, until the holder answers (`crate::sync::custody`). A
//! surface that seals the input itself hands the console no plaintext; an
//! upload of the raw value to the holder stays an explicit choice.
//!
//! A kept or relayed input carries its request's signed entry as a witness
//! (FIX 4996), beside the envelope and outside the digest the request names,
//! since the request names that digest: a window admits an input row only
//! on a witness that proves the row names a real request for it.
//!
//! An input longer than one row carries, as a register framed with its
//! manifest's text or a sealed register with every manifest the vault
//! publishes attached may be, travels in numbered parts (Rule 5: split,
//! never skip; CALLS CUSTODY_MANIFEST_UNSTATED_MULTI). No seal, door or
//! open refuses an input for its whole length (FIX 5445): a body past one
//! envelope's plaintext bound seals as numbered envelopes, each within it
//! (FIX 5521, `envelopes`), and each row keeps the 4 MiB bound. Each
//! part row carries its index, every part's digest and its own bytes, and
//! the digest the request names is over that list, so one 32-byte digest
//! commits to the whole input and each part is checked on its own as it is
//! admitted. The holder reads the parts in order as it opens the input,
//! never joining them; while one is missing, the request stays pending.
//!
//! A door reads the input its owner's surface sealed where it lies, a file
//! or a buffer, never as one buffer (FIX 11140, `stream`): it computes the
//! digest part by part and keeps the input row by row. One it seals in
//! numbered carrier parts it reads once, staging each row as it is sealed
//! and digesting it as it is staged (FIX 12177, `door_rows`).
//!
//! A witness past one row's bound travels in signed numbered parts of its
//! own, and each input row carries a signed reference to them (FIX 8088,
//! `witness`).
//!
//! While the carrier wire is on, an input is sealed under its own erasable
//! carrier key first, a surface's past one row in numbered parts (FIX
//! 12148), and the recorder retires that key once its request is answered
//! (FIX 7402, `carrier_seal`).

mod attached;
mod carrier_seal;
mod door_rows;
mod envelopes;
#[cfg(oneiron_test_support)]
mod numbered_test;
mod relayed;
mod stream;
mod surface_seal;
mod witness;

use std::io::Read;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use crate::Vault;
use crate::authority::{AuthorityEntryHash, CustodyChange, CustodyPermitSet, WrapRecipient};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::world_keys::MachineSecret;
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

pub(crate) use self::attached::{
    Attached, AttachedManifest, Attachment, attach_manifest, attach_no_manifest,
    attach_published_manifests, attach_unread,
};
pub(crate) use self::carrier_seal::{
    LeafSource, SurfaceLeaf, SurfaceRetry, input_carrier_binds, input_carrier_in_txn,
    open_leaf_input, retire_input_carriers_in_txn, seal_leaf_input_in_txn, seal_leaf_parts_in_txn,
    surface_leaf_input, surface_retry_in_txn,
};
pub(crate) use self::door_rows::DoorInput;
#[cfg(oneiron_test_support)]
pub(crate) use self::envelopes::{
    frame_envelope_count_for_test, tamper_drop_first_envelope_for_test,
    tamper_rewrite_envelope_count_for_test, tamper_swap_first_two_envelopes_for_test,
};
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) use self::numbered_test::{
    KeptNumberedOpen, drop_kept_numbered_part_for_test, keep_numbered_input_for_test,
    open_kept_numbered_for_test,
};
#[cfg(oneiron_test_support)]
pub(crate) use self::numbered_test::{
    open_numbered_as_holder_for_test, seal_numbered_register_for_test,
};
pub(crate) use self::relayed::{InputPart, RelayedInput};
pub use self::stream::SealedInput;
pub(crate) use self::stream::{InputDigests, SealedFrame, kept_input_in_txn};
pub use self::surface_seal::{CustodyInputBinding, seal_custody_input};
#[cfg(oneiron_test_support)]
pub(crate) use self::witness::custody_witness_digest_for_test;
#[cfg(oneiron_test_support)]
pub(crate) use self::witness::custody_witness_part_key_for_test;
pub(crate) use self::witness::{WitnessJoin, keep_witnessed_input_in_txn, witness_joined_in_txn};
#[cfg(feature = "sync")]
pub(crate) use self::witness::{
    WitnessPart, held_witness_in_txn, held_witnesses, keep_witness_in_txn,
};

const INPUT_LABEL: &[u8] = b"oneiron/custody-input/v1";
const KEY_ID_LABEL: &[u8] = b"custody-input/v1";
const BINDING_DOMAIN: &[u8] = b"oneiron/custody-input-binding/v1";
const DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-digest/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The most bytes of an input one relayed row carries, as for a custody
/// transition: a longer input, its envelope with whatever its recorder
/// attached, splits into parts of at most this many bytes. It bounds a row,
/// never the whole input (FIX 5445).
pub(crate) const MAX_INPUT_BYTES: usize = 4 << 20;
/// The most bytes of an input one part carries.
const PART_BYTES: usize = MAX_INPUT_BYTES;
/// The most parts one split input lists: its part digests fill at most one
/// row's bound (the part list's own codec bound, past 500 GiB of input).
const MAX_PARTS: usize = MAX_INPUT_BYTES / 32;
/// The label of one part of a split input's row body: the part's index and
/// the part count, each a `u32`, every part's digest in order, then the
/// part's bytes.
const PART_LABEL: &[u8] = b"oneiron/custody-input-part/v1\0";
const PART_DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-part-digest/v1";
const PARTS_DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-parts-digest/v1";

/// Each input row this vault keeps to relay, or keeps as its holder until
/// it answers: a whole input by the digest its request names, a part of a
/// split one by its own key.
const INPUTS: SideTable<[u8; 32], Vec<u8>, Raw> = SideTable::new(&side_table::SECRET_CUSTODY_INPUT);

/// What one input binds: every field of the request it is for but the
/// request's own hash, which it precedes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InputBinding<'a> {
    pub(crate) vault_id: [u8; 32],
    pub(crate) id: EntityId,
    pub(crate) change: CustodyChange,
    pub(crate) generation: u32,
    pub(crate) seen: [u8; 32],
    pub(crate) holder: EntityId,
    pub(crate) permits: &'a CustodyPermitSet,
}

impl InputBinding<'_> {
    /// A one-envelope input's key id: a label, then a digest of every bound
    /// field, within the envelope's 64-byte id. A numbered envelope's adds
    /// its place (`envelopes`).
    fn key_id(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BINDING_DOMAIN);
        hasher.update(&self.vault_id);
        hasher.update(self.id.as_bytes());
        hasher.update(self.change.as_str().as_bytes());
        hasher.update(&[0]);
        hasher.update(&self.generation.to_be_bytes());
        hasher.update(&self.seen);
        hasher.update(self.holder.as_bytes());
        hasher.update(&(self.permits.len() as u32).to_be_bytes());
        for permit in self.permits {
            hasher.update(permit.machine.as_bytes());
            hasher.update(&permit.profile);
            hasher.update(&permit.encryption_key);
        }
        let mut out = Vec::with_capacity(KEY_ID_LABEL.len() + 32);
        out.extend_from_slice(KEY_ID_LABEL);
        out.extend_from_slice(hasher.finalize().as_bytes());
        out
    }

    /// Seals `body` to the holder's `key` under this binding: the input's
    /// bytes. A body that fits one envelope seals as one, the form an input
    /// has always had; a longer one as numbered envelopes in one frame
    /// (FIX 5521, `envelopes`). Either is carried past one row's bound in
    /// numbered parts (FIX 5445). Nothing refuses its length but the codec
    /// bounds of one envelope and of the frame.
    pub(crate) fn seal(&self, key: &HybridPublicKey, body: &[u8]) -> Result<Vec<u8>> {
        if envelopes::fits_one(body) {
            self.seal_one(key, body, &self.key_id())
        } else {
            self.seal_numbered(key, body)
        }
    }

    /// Seals `body`, within one envelope's bound, to the holder's `key` as
    /// one envelope under `key_id`.
    fn seal_one(&self, key: &HybridPublicKey, body: &[u8], key_id: &[u8]) -> Result<Vec<u8>> {
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let mut payload = Zeroizing::new(Vec::with_capacity(INPUT_LABEL.len() + body.len()));
        payload.extend_from_slice(INPUT_LABEL);
        payload.extend_from_slice(body);
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SecretFile,
            epoch: EPOCH,
            key_id,
            recipient: &recipient,
            vault_id: &self.vault_id,
        };
        seal(
            &params,
            SealKey::Hybrid {
                recipient: key,
                kem_suite: KEM,
            },
            &payload,
            &mut SysRng,
        )
        .map(|envelope| envelope.to_bytes())
        .map_err(|_| refused("sealing the custody input to its holder failed"))
    }

    /// The body the input of `len` bytes `reader` holds, opened with the
    /// holder's `secret` under this binding as it is read: one envelope, or
    /// every numbered envelope of a frame, each opened and verified at its
    /// place before the next is read and the runs joined (FIX 5521, 11140).
    /// `None` when `secret` is not the holder's, an envelope does not parse
    /// under its codec, or one was sealed to another key, under another
    /// binding or at another place. Its length past one row's bound is no
    /// reason: such an input is read from its parts in order (FIX 5445).
    pub(crate) fn open(
        &self,
        reader: impl Read,
        len: u64,
        secret: &MachineSecret,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if secret.machine != self.holder {
            return None;
        }
        self.open_read(reader, len, secret)
    }

    /// The body one `envelope` holds, opened with the holder's `secret`
    /// under `key_id`.
    fn open_one(
        &self,
        envelope: &[u8],
        secret: &MachineSecret,
        key_id: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let envelope = Envelope::parse(envelope).ok()?;
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let policy = OpenPolicy {
            purpose: Purpose::SecretFile,
            vault_id: &self.vault_id,
            recipient: &recipient,
            key_id,
            wraps: &[WrapType::HybridCapsule],
            aead_suites: &[AEAD],
            kem_suites: &[KEM],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let payload = envelope
            .open(OpenKey::Hybrid(&secret.secret), &policy)
            .ok()?;
        let body = payload.strip_prefix(INPUT_LABEL)?;
        Some(Zeroizing::new(body.to_vec()))
    }
}

/// The digest a request names of its input: over the ciphertext alone, so
/// it says nothing of the value. For an input that travels in parts, over
/// the list of its parts' digests, each over that part's bytes alone.
pub(crate) fn input_digest(input: &[u8]) -> [u8; 32] {
    if splits(input) {
        parts_digest(
            &input
                .chunks(PART_BYTES)
                .map(part_digest)
                .collect::<Vec<_>>(),
        )
    } else {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }
}

/// Whether `input` travels in parts: it is longer than one row carries, or
/// its own bytes would read as a part.
fn splits(input: &[u8]) -> bool {
    input.len() > PART_BYTES || input.starts_with(PART_LABEL)
}

/// One part's digest, over its bytes alone.
fn part_digest(bytes: &[u8]) -> [u8; 32] {
    *part_hasher().update(bytes).finalize().as_bytes()
}

/// A part's digest before its bytes, which [`part_digest`] takes whole and
/// a reader may feed in runs (FIX 12177).
fn part_hasher() -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PART_DIGEST_DOMAIN);
    hasher
}

/// A split input's digest: over its part count and every part's digest, in
/// order.
fn parts_digest(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PARTS_DIGEST_DOMAIN);
    hasher.update(&(digests.len() as u64).to_be_bytes());
    for digest in digests {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

/// The key part `index` of the split input the request names `digest` of
/// is kept and relayed under. Peers recompute it to find the row, so it keeps
/// its bytes (K, PLAN-UC-04 stage 5).
fn part_key(digest: &[u8; 32], index: u32) -> [u8; 32] {
    LegacyDigest::new(purposes::secret::CUSTODY_INPUT_PART_KEY)
        .raw(digest)
        .raw(&index.to_be_bytes())
        .finish()
}

#[cfg(oneiron_test_support)]
pub(crate) fn custody_input_part_key_for_test(digest: &[u8; 32], index: u32) -> [u8; 32] {
    part_key(digest, index)
}

/// The witness of the request signed as entry `hash` (FIX 4996): its stored
/// entry, canonical, which hashes to `hash`.
///
/// # Errors
/// No authority row is stored under `hash`; storage errors.
pub(crate) fn request_witness_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
) -> Result<Vec<u8>> {
    let entry = crate::authority::stored_authority_row(&vault.store, txn, hash)?
        .ok_or_else(crate::authority::invalid_authority)?;
    crate::authority::encode_authority_log_entry_body(&entry)
}

/// Keeps `input` in `wtxn`, each row under its key: a whole input that
/// fits one row as it is, a longer one as its numbered parts, and a relayed
/// part as it came.
#[cfg(feature = "sync")]
pub(crate) fn keep_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &RelayedInput,
) -> Result<()> {
    let parts = input.parts()?;
    for row in parts.as_deref().unwrap_or(std::slice::from_ref(input)) {
        INPUTS.put(&vault.store, wtxn, &row.row_key(), &row.encode())?;
    }
    Ok(())
}

/// The input row kept under `key`, when it decodes.
pub(crate) fn held_input_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<RelayedInput>> {
    Ok(INPUTS
        .get(store, txn, key)?
        .and_then(|bytes| RelayedInput::decode(&bytes)))
}

/// Forgets the input the request names `digest` of: its whole row, or each
/// of its parts, then each other row found by the digest it names, a first
/// part missing included, and every part of its witness (FIX 8088). A fault
/// finding those is warned and never undoes the rest: they, and a part
/// that arrives later, go with the answered request
/// ([`Vault::settle_custody_inputs`]).
pub(crate) fn drop_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    let parts = held_input_in_txn(&vault.store, wtxn, &part_key(digest, 0))?
        .and_then(|row| row.part)
        .map_or(0, |part| part.digests.len());
    INPUTS.delete(&vault.store, wtxn, digest)?;
    for index in (0_u32..).take(parts) {
        INPUTS.delete(&vault.store, wtxn, &part_key(digest, index))?;
    }
    if let Err(error) = witness::drop_rows_of_in_txn(vault, wtxn, digest) {
        tracing::warn!(kind = ?error.kind(), "an input's other rows stay for its settle");
    }
    Ok(())
}

/// Forgets every input row kept for a request on record `id`, each part of
/// a split one too: a revoke leaves no pending input of it (CALLS
/// CUSTODY_REVOKE_ERASE). Returns how many rows it forgot.
pub(crate) fn drop_inputs_for_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<usize> {
    let fold = vault.authority_view_readonly_in_txn(wtxn)?;
    drop_inputs_with_fold_in_txn(&vault.store, wtxn, id, &fold)
}

pub(super) fn drop_inputs_with_fold_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    fold: &crate::authority::AuthorityFold,
) -> Result<usize> {
    let doomed: Vec<([u8; 32], Vec<u8>)> = INPUTS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, bytes)| {
            RelayedInput::decode(bytes).is_some_and(|input| {
                fold.owner_work_request(&input.request)
                    .is_some_and(|request| request.act.target == *id)
            })
        })
        .collect();
    // Their carrier keys go with them (FIX 7402).
    let carriers: Vec<_> = doomed
        .iter()
        .filter_map(|(_, bytes)| carrier_seal::row_carrier(bytes))
        .collect();
    retire_input_carriers_in_txn(store, wtxn, &carriers);
    for (key, _) in &doomed {
        INPUTS.delete(store, wtxn, key)?;
    }
    // Every witness part kept for such a request goes too (FIX 8088); a
    // fault finding them is warned, and they go with the settle.
    let witnesses = witness::drop_witnesses_for_store_in_txn(store, wtxn, |group| {
        witness::witness_target(fold, group) == Some(*id)
    })
    .unwrap_or_else(|error| {
        tracing::warn!(kind = ?error.kind(), "a revoked secret's witness parts stay for its settle");
        0
    });
    Ok(doomed.len() + witnesses)
}

/// Every input row this vault keeps, by its key, as stored.
#[cfg(feature = "sync")]
pub(crate) fn held_inputs(vault: &Vault) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    INPUTS.scan(&vault.store, &rtxn)
}

impl Vault {
    /// Forgets every kept input row, whole or part, whose request is
    /// answered, is on a secret an admitted revoke ended, or that this
    /// install folds as no admitted request at all: what remains is the
    /// relay of work still awaiting its holder. The owner work drain runs it
    /// beside the revoke settle. Returns how many rows it forgot.
    pub(crate) fn settle_custody_inputs(&self) -> Result<usize> {
        let (done, carriers, witnesses) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let settled = |request: &AuthorityEntryHash| {
                fold.owner_work_result(request).is_some()
                    || fold
                        .owner_work_request(request)
                        .is_none_or(|request| fold.custody_revoked(&request.act.target))
            };
            let done: Vec<([u8; 32], Vec<u8>)> = INPUTS
                .scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, bytes)| {
                    RelayedInput::decode(bytes).is_none_or(|input| settled(&input.request))
                })
                .collect();
            // An answered input's carrier key retires here, where its
            // recorder minted it (FIX 7402).
            let carriers: Vec<_> = done
                .iter()
                .filter_map(|(_, bytes)| carrier_seal::row_carrier(bytes))
                .collect();
            // So does every witness part kept for one (FIX 8088); a fault
            // finding them is warned, and the next settle retries.
            let witnesses = witness::settled_witnesses_in_txn(&self.store, &txn, settled)
                .unwrap_or_else(|error| {
                    tracing::warn!(kind = ?error.kind(), "settled witness parts stay owed");
                    Vec::new()
                });
            (done, carriers, witnesses)
        };
        if done.is_empty() && witnesses.is_empty() {
            return Ok(0);
        }
        let forgot = self.with_write_txn(|txn| {
            retire_input_carriers_in_txn(&self.store, txn, &carriers);
            for (key, _) in &done {
                INPUTS.delete(&self.store, txn, key)?;
            }
            if let Err(error) = witness::delete_witnesses_in_txn(self, txn, &witnesses) {
                tracing::warn!(kind = ?error.kind(), "settled witness parts stay owed");
                return Ok(done.len());
            }
            Ok(done.len() + witnesses.len())
        })?;
        if !carriers.is_empty() {
            self.finish_credential_retirements_after_commit();
        }
        Ok(forgot)
    }
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("{reason}; nothing was written"))
}
