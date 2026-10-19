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
//! An input longer than one row carries, as a sealed register with every
//! manifest the vault publishes attached may be, travels in numbered parts
//! (Rule 5: split, never skip; CALLS CUSTODY_MANIFEST_UNSTATED_MULTI). Each
//! part row carries its index, every part's digest and its own bytes, and
//! the digest the request names is over that list, so one 32-byte digest
//! commits to the whole input and each part is checked on its own as it is
//! admitted. The holder joins the parts before it opens the input; while one
//! is missing, the request stays pending.

mod attached;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use crate::Vault;
use crate::authority::{AuthorityEntryHash, CustodyChange, CustodyRecipientPermit, WrapRecipient};
#[cfg(feature = "sync")]
use crate::authority::{
    AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityOp, OwnerWorkBody, OwnerWorkRequest,
    authority_entry_hash, decode_authority_log_entry_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::world_keys::MachineSecret;

pub(crate) use self::attached::{
    Attached, AttachedManifest, attach_manifest, attach_no_manifest, attach_published_manifests,
    attach_unread, split_attached,
};

const INPUT_LABEL: &[u8] = b"oneiron/custody-input/v1";
const KEY_ID_LABEL: &[u8] = b"custody-input/v1";
const BINDING_DOMAIN: &[u8] = b"oneiron/custody-input-binding/v1";
const DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-digest/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The largest input envelope a door takes, as for a custody transition,
/// and the most bytes of an input one relayed row carries: a longer input
/// splits into parts of at most this many bytes.
pub(crate) const MAX_INPUT_BYTES: usize = 4 << 20;
/// A relayed input's frame: the second it was sealed at, the request, then
/// its witness's length. The witness and the row's body follow, each at most
/// [`MAX_INPUT_BYTES`]: the whole input, or one part of it.
const FRAME_BYTES: usize = 8 + 32 + 4;
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
const PART_KEY_DOMAIN: &[u8] = b"oneiron/custody-input-part-key/v1";

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
    pub(crate) permits: &'a [CustodyRecipientPermit],
}

impl InputBinding<'_> {
    /// The envelope key id: a label, then a digest of every bound field,
    /// within the envelope's 64-byte id.
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
    /// envelope bytes.
    pub(crate) fn seal(&self, key: &HybridPublicKey, body: &[u8]) -> Result<Vec<u8>> {
        let key_id = self.key_id();
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let mut payload = Zeroizing::new(Vec::with_capacity(INPUT_LABEL.len() + body.len()));
        payload.extend_from_slice(INPUT_LABEL);
        payload.extend_from_slice(body);
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SecretFile,
            epoch: EPOCH,
            key_id: &key_id,
            recipient: &recipient,
            vault_id: &self.vault_id,
        };
        let envelope = seal(
            &params,
            SealKey::Hybrid {
                recipient: key,
                kem_suite: KEM,
            },
            &payload,
            &mut SysRng,
        )
        .map(|envelope| envelope.to_bytes())
        .map_err(|_| refused("sealing the custody input to its holder failed"))?;
        if envelope.len() > MAX_INPUT_BYTES {
            return Err(refused(
                "the custody input is larger than one custody transition carries",
            ));
        }
        Ok(envelope)
    }

    /// The body `envelope` holds, opened with the holder's `secret` under
    /// this binding. `None` when `secret` is not the holder's, or the
    /// envelope was sealed to another key or under another binding.
    pub(crate) fn open(
        &self,
        envelope: &[u8],
        secret: &MachineSecret,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if secret.machine != self.holder || envelope.len() > MAX_INPUT_BYTES {
            return None;
        }
        let envelope = Envelope::parse(envelope).ok()?;
        let key_id = self.key_id();
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let policy = OpenPolicy {
            purpose: Purpose::SecretFile,
            vault_id: &self.vault_id,
            recipient: &recipient,
            key_id: &key_id,
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
    let mut hasher = blake3::Hasher::new();
    hasher.update(PART_DIGEST_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
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
/// is kept and relayed under.
fn part_key(digest: &[u8; 32], index: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PART_KEY_DOMAIN);
    hasher.update(digest);
    hasher.update(&index.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Where one row's bytes sit in a split input: the part's index, and every
/// part's digest in order, which the digest the request names is over.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InputPart {
    index: u32,
    digests: Vec<[u8; 32]>,
}

/// One input as it is kept and relayed: the second it was sealed at, whose
/// month's base window carries it, the request it is for, that request's
/// witness and its envelope, whole or one part of it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RelayedInput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The request's signed authority entry, canonical (FIX 4996). It rides
    /// outside the envelope's digest, which the request names.
    pub(crate) witness: Vec<u8>,
    /// Where `envelope` sits in the input the request names; `None` while
    /// it is the whole.
    pub(crate) part: Option<InputPart>,
    /// The whole input, or this part's bytes.
    pub(crate) envelope: Vec<u8>,
}

/// What an input's witness proves: the request, and the install key that
/// signed it, when it is one.
#[cfg(feature = "sync")]
pub(crate) struct Witnessed {
    key: Option<[u8; 32]>,
    request: OwnerWorkRequest,
}

#[cfg(feature = "sync")]
impl Witnessed {
    /// Whether `fold` judged the request entry `hash` invalid with its
    /// signer folded (FIX 4996): a chain of its carrier names the key that
    /// signed it, and the fold holds an issue for exactly this entry, other
    /// than one that waits on a parent not here yet.
    pub(crate) fn folded_invalid(&self, fold: &AuthorityFold, hash: &AuthorityEntryHash) -> bool {
        let Some(key) = &self.key else {
            return false;
        };
        fold.machine(self.request.carrier)
            .is_some_and(|machine| machine.names_key(key))
            && fold.issues.iter().any(|issue| match issue {
                AuthorityFoldIssue::InvalidEntry(entry)
                | AuthorityFoldIssue::RetiredSigner(entry)
                | AuthorityFoldIssue::SignerNotInAncestry(entry)
                | AuthorityFoldIssue::NonMonotonicSeq(entry)
                | AuthorityFoldIssue::WrongVault(entry) => entry == hash,
                _ => false,
            })
    }
}

// Never print the ciphertext.
impl std::fmt::Debug for RelayedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayedInput")
            .field("sealed_at", &self.sealed_at)
            .field(
                "part",
                &self
                    .part
                    .as_ref()
                    .map(|part| (part.index, part.digests.len())),
            )
            .field("bytes", &self.envelope.len())
            .finish_non_exhaustive()
    }
}

impl RelayedInput {
    /// The frame, the witness, then the body: the envelope, or for a part
    /// its label, index, part count and part digests, then its bytes. A
    /// witness longer than a `u32` is never framed: [`Self::decode`] refuses
    /// one past [`MAX_INPUT_BYTES`].
    pub(crate) fn encode(&self) -> Vec<u8> {
        let witness_len = u32::try_from(self.witness.len()).unwrap_or(u32::MAX);
        let listed = self.part.as_ref().map_or(0, |part| part.digests.len());
        let mut out = Vec::with_capacity(
            FRAME_BYTES
                + self.witness.len()
                + PART_LABEL.len()
                + 8
                + 32 * listed
                + self.envelope.len(),
        );
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&witness_len.to_be_bytes());
        out.extend_from_slice(&self.witness);
        if let Some(part) = &self.part {
            out.extend_from_slice(PART_LABEL);
            out.extend_from_slice(&part.index.to_be_bytes());
            out.extend_from_slice(&u32::try_from(listed).unwrap_or(u32::MAX).to_be_bytes());
            for digest in &part.digests {
                out.extend_from_slice(digest);
            }
        }
        out.extend_from_slice(&self.envelope);
        out
    }

    /// Decodes a kept or relayed input strictly; `None` for a short frame,
    /// a zero request, an empty or oversized witness or envelope, or a part
    /// whose index is outside its list, whose list is empty or past
    /// [`MAX_PARTS`], or whose bytes are not the digest its list names for
    /// it. The witness is read, not judged: [`Self::witnessed`] judges it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (sealed_at, rest) = bytes.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let (witness, body) =
            rest.split_at_checked(usize::try_from(u32::from_be_bytes(*witness_len)).ok()?)?;
        let (part, envelope) = match body.strip_prefix(PART_LABEL) {
            None => (None, body),
            Some(rest) => {
                let (part, bytes) = InputPart::decode(rest)?;
                (Some(part), bytes)
            }
        };
        if *request == [0; 32]
            || witness.is_empty()
            || witness.len() > MAX_INPUT_BYTES
            || envelope.is_empty()
            || envelope.len() > MAX_INPUT_BYTES
        {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            witness: witness.to_vec(),
            part,
            envelope: envelope.to_vec(),
        })
    }

    /// The key this row is kept and relayed under: the digest the request
    /// names for a whole input, else this part's own key under it.
    pub(crate) fn row_key(&self) -> [u8; 32] {
        match &self.part {
            Some(part) => part_key(&self.digest(), part.index),
            None => self.digest(),
        }
    }

    /// The rows that carry this whole input when it travels in parts: each
    /// numbered part, in order, every one with the witness and the part
    /// list. `None` when it fits one row, or is a part already. Refused only
    /// past the part list's own bound.
    fn parts(&self) -> Result<Option<Vec<Self>>> {
        if self.part.is_some() || !splits(&self.envelope) {
            return Ok(None);
        }
        let digests: Vec<[u8; 32]> = self.envelope.chunks(PART_BYTES).map(part_digest).collect();
        if digests.len() > MAX_PARTS {
            return Err(refused(
                "the custody input splits into more parts than one part list names",
            ));
        }
        Ok(Some(
            self.envelope
                .chunks(PART_BYTES)
                .zip(0_u32..)
                .map(|(bytes, index)| Self {
                    sealed_at: self.sealed_at,
                    request: self.request,
                    witness: self.witness.clone(),
                    part: Some(InputPart {
                        index,
                        digests: digests.clone(),
                    }),
                    envelope: bytes.to_vec(),
                })
                .collect(),
        ))
    }

    /// The request this input's witness proves (FIX 4996): the witness is a
    /// canonical authority entry whose signature verifies, it hashes to
    /// `request`, and it is a custody request naming this input's digest.
    /// `None` otherwise.
    #[cfg(feature = "sync")]
    pub(crate) fn witnessed(&self) -> Option<Witnessed> {
        let entry = decode_authority_log_entry_body(&self.witness).ok()?;
        if authority_entry_hash(&entry).ok()? != self.request {
            return None;
        }
        let key = match entry.signer_key() {
            AuthorityKey::Ed25519(key) => Some(*key),
            _ => None,
        };
        let AuthorityOp::OwnerWorkRequest(request) = entry.op else {
            return None;
        };
        let digest = self.digest();
        matches!(
            &request.work,
            OwnerWorkBody::Custody { input: Some(named), .. } if *named == digest
        )
        .then_some(Witnessed { key, request })
    }

    /// The digest the request names: of the whole input, or for a part,
    /// over its list of part digests.
    pub(crate) fn digest(&self) -> [u8; 32] {
        match &self.part {
            Some(part) => parts_digest(&part.digests),
            None => input_digest(&self.envelope),
        }
    }
}

impl InputPart {
    /// A part's index, part count and part digests, then its bytes, which
    /// must be the digest its list names for it.
    fn decode(body: &[u8]) -> Option<(Self, &[u8])> {
        let (index, rest) = body.split_first_chunk::<4>()?;
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let count = usize::try_from(u32::from_be_bytes(*count)).ok()?;
        if count == 0 || count > MAX_PARTS {
            return None;
        }
        let (listed, bytes) = rest.split_at_checked(count.checked_mul(32)?)?;
        let digests = listed
            .chunks_exact(32)
            .map(|digest| <[u8; 32]>::try_from(digest).ok())
            .collect::<Option<Vec<_>>>()?;
        let index = u32::from_be_bytes(*index);
        let named = digests.get(usize::try_from(index).ok()?)?;
        (part_digest(bytes) == *named).then_some((Self { index, digests }, bytes))
    }
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

/// The input the request names `digest` of, as this vault keeps it: its
/// whole row, or every part of it joined in order, each part checked
/// against the part list `digest` is over. `None` while it, or any part of
/// it, is not here: the request stays pending.
pub(crate) fn assembled_input_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if let Some(whole) = held_input_in_txn(store, txn, digest)?
        && whole.part.is_none()
        && whole.digest() == *digest
    {
        return Ok(Some(whole.envelope));
    }
    let mut joined = Vec::new();
    let mut index = 0_u32;
    loop {
        let Some(row) = held_input_in_txn(store, txn, &part_key(digest, index))? else {
            return Ok(None);
        };
        let Some(part) = &row.part else {
            return Ok(None);
        };
        if part.index != index || parts_digest(&part.digests) != *digest {
            return Ok(None);
        }
        let count = part.digests.len();
        joined.extend_from_slice(&row.envelope);
        index += 1;
        if usize::try_from(index).is_ok_and(|done| done == count) {
            return Ok(Some(joined));
        }
    }
}

/// Forgets the input the request names `digest` of: its whole row, or each
/// of its parts. A part left behind goes with the answered request
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
    let doomed: Vec<[u8; 32]> = INPUTS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, bytes)| {
            RelayedInput::decode(bytes).is_some_and(|input| {
                fold.owner_work_request(&input.request)
                    .is_some_and(|request| request.act.target == *id)
            })
        })
        .map(|(key, _)| key)
        .collect();
    for key in &doomed {
        INPUTS.delete(&vault.store, wtxn, key)?;
    }
    Ok(doomed.len())
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
        let done: Vec<[u8; 32]> = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            INPUTS
                .scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, bytes)| {
                    RelayedInput::decode(bytes).is_none_or(|input| {
                        fold.owner_work_result(&input.request).is_some()
                            || fold
                                .owner_work_request(&input.request)
                                .is_none_or(|request| fold.custody_revoked(&request.act.target))
                    })
                })
                .map(|(key, _)| key)
                .collect()
        };
        if done.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|txn| {
            for key in &done {
                INPUTS.delete(&self.store, txn, key)?;
            }
            Ok(done.len())
        })
    }
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("{reason}; nothing was written"))
}
