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

const INPUT_LABEL: &[u8] = b"oneiron/custody-input/v1";
const KEY_ID_LABEL: &[u8] = b"custody-input/v1";
const BINDING_DOMAIN: &[u8] = b"oneiron/custody-input-binding/v1";
const DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-digest/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The largest input envelope a door takes or a relay carries, as for a
/// custody transition.
pub(crate) const MAX_INPUT_BYTES: usize = 4 << 20;
/// A relayed input's frame: the second it was sealed at, the request, then
/// its witness's length. The witness and the envelope follow, each at most
/// [`MAX_INPUT_BYTES`].
const FRAME_BYTES: usize = 8 + 32 + 4;
/// The label of a sealed register's input as its recorder records it: the
/// envelope the owner's surface sealed, then the manifest the recorder
/// resolved for the `manifest_ref` that surface stated (CALLS
/// CUSTODY_MANIFEST_RECHECK). The request names the digest of the whole, so
/// the manifest is the recorder's as the envelope is the surface's.
const ATTACHED_LABEL: &[u8] = b"oneiron/custody-input-attached/v1\0";
/// The label of a sealed register's input whose surface stated no
/// `manifest_ref`: the envelope, then the vault's one current approved
/// manifest its recorder found (CALLS CUSTODY_MANIFEST_UNSTATED).
const CURRENT_LABEL: &[u8] = b"oneiron/custody-input-current/v1\0";
/// The label of a sealed register's input whose surface stated no
/// `manifest_ref` and for which its recorder found no current approved
/// manifest: the envelope alone, registered without a manifest check (CALLS
/// CUSTODY_MANIFEST_UNSTATED).
const NO_MANIFEST_LABEL: &[u8] = b"oneiron/custody-input-no-manifest/v1\0";

/// Each input this vault keeps to relay, or keeps as its holder until it
/// answers, by its ciphertext digest.
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

/// The manifest a recorder resolved for a sealed register and attached to
/// its input: the `manifest_ref` it resolved and the file's text.
pub(crate) struct AttachedManifest {
    pub(crate) manifest_ref: String,
    pub(crate) text: String,
}

/// What a sealed register's recorder attached beside the envelope its
/// owner's surface sealed, under the digest the request names.
pub(crate) enum Attached {
    /// The manifest it resolved for the `manifest_ref` the surface stated
    /// (CALLS CUSTODY_MANIFEST_RECHECK).
    Stated(AttachedManifest),
    /// The surface stated none: the vault's one current approved manifest
    /// (CALLS CUSTODY_MANIFEST_UNSTATED).
    Current(AttachedManifest),
    /// The surface stated none and no current approved manifest applied:
    /// the record registers without a manifest check.
    NoManifest,
}

/// A sealed register's `envelope` with the manifest its recorder resolved
/// for it attached: what the request then names the digest of.
pub(crate) fn attach_manifest(envelope: &[u8], manifest_ref: &str, text: &str) -> Result<Vec<u8>> {
    frame_attached(ATTACHED_LABEL, envelope, Some((manifest_ref, text)))
}

/// A sealed register's `envelope` whose surface stated no `manifest_ref`,
/// with the vault's one current approved manifest attached (CALLS
/// CUSTODY_MANIFEST_UNSTATED).
pub(crate) fn attach_current_manifest(
    envelope: &[u8],
    manifest_ref: &str,
    text: &str,
) -> Result<Vec<u8>> {
    frame_attached(CURRENT_LABEL, envelope, Some((manifest_ref, text)))
}

/// A sealed register's `envelope` whose surface stated no `manifest_ref`,
/// marked as carrying no manifest (CALLS CUSTODY_MANIFEST_UNSTATED).
pub(crate) fn attach_no_manifest(envelope: &[u8]) -> Result<Vec<u8>> {
    frame_attached(NO_MANIFEST_LABEL, envelope, None)
}

/// `label`, the envelope's length and bytes, then the manifest's ref
/// length, ref and text when there is one; refused past one input's bound.
fn frame_attached(
    label: &[u8],
    envelope: &[u8],
    manifest: Option<(&str, &str)>,
) -> Result<Vec<u8>> {
    let too_large = || {
        refused("the sealed input and its manifest are larger than one custody transition carries")
    };
    let envelope_len = u32::try_from(envelope.len()).map_err(|_| too_large())?;
    let (manifest_ref, text) = manifest.unwrap_or_default();
    let mut out =
        Vec::with_capacity(label.len() + 8 + envelope.len() + manifest_ref.len() + text.len());
    out.extend_from_slice(label);
    out.extend_from_slice(&envelope_len.to_be_bytes());
    out.extend_from_slice(envelope);
    if manifest.is_some() {
        let ref_len = u32::try_from(manifest_ref.len()).map_err(|_| too_large())?;
        out.extend_from_slice(&ref_len.to_be_bytes());
        out.extend_from_slice(manifest_ref.as_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    if out.len() > MAX_INPUT_BYTES {
        return Err(too_large());
    }
    Ok(out)
}

/// The envelope a kept input holds, and what its recorder attached, if
/// anything; `None` for a malformed attachment.
pub(crate) fn split_attached(kept: &[u8]) -> Option<(&[u8], Option<Attached>)> {
    let (rest, kind): (&[u8], fn(AttachedManifest) -> Attached) =
        if let Some(rest) = kept.strip_prefix(ATTACHED_LABEL) {
            (rest, Attached::Stated)
        } else if let Some(rest) = kept.strip_prefix(CURRENT_LABEL) {
            (rest, Attached::Current)
        } else if let Some(rest) = kept.strip_prefix(NO_MANIFEST_LABEL) {
            let (len, envelope) = rest.split_first_chunk::<4>()?;
            return (usize::try_from(u32::from_be_bytes(*len)).ok()? == envelope.len())
                .then_some((envelope, Some(Attached::NoManifest)));
        } else {
            return Some((kept, None));
        };
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let (envelope, rest) =
        rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)?;
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let (manifest_ref, text) =
        rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)?;
    let attached = AttachedManifest {
        manifest_ref: std::str::from_utf8(manifest_ref).ok()?.to_owned(),
        text: std::str::from_utf8(text).ok()?.to_owned(),
    };
    Some((envelope, Some(kind(attached))))
}

/// The digest a request names of its input: over the ciphertext alone, so
/// it says nothing of the value.
pub(crate) fn input_digest(envelope: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(envelope);
    *hasher.finalize().as_bytes()
}

/// One input as it is kept and relayed: the second it was sealed at, whose
/// month's base window carries it, the request it is for, that request's
/// witness and its envelope.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RelayedInput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The request's signed authority entry, canonical (FIX 4996). It rides
    /// outside the envelope's digest, which the request names.
    pub(crate) witness: Vec<u8>,
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
            .field("bytes", &self.envelope.len())
            .finish_non_exhaustive()
    }
}

impl RelayedInput {
    /// The frame, the witness, then the envelope. A witness longer than a
    /// `u32` is never framed: [`Self::decode`] refuses one past
    /// [`MAX_INPUT_BYTES`].
    pub(crate) fn encode(&self) -> Vec<u8> {
        let witness_len = u32::try_from(self.witness.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(FRAME_BYTES + self.witness.len() + self.envelope.len());
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&witness_len.to_be_bytes());
        out.extend_from_slice(&self.witness);
        out.extend_from_slice(&self.envelope);
        out
    }

    /// Decodes a kept or relayed input strictly; `None` for a short frame,
    /// a zero request, or an empty or oversized witness or envelope. The
    /// witness is read, not judged: [`Self::witnessed`] judges it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (sealed_at, rest) = bytes.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let (witness, envelope) =
            rest.split_at_checked(usize::try_from(u32::from_be_bytes(*witness_len)).ok()?)?;
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
            envelope: envelope.to_vec(),
        })
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

    /// The digest the request names.
    pub(crate) fn digest(&self) -> [u8; 32] {
        input_digest(&self.envelope)
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

/// Keeps `input` under its digest in `wtxn`.
pub(crate) fn keep_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &RelayedInput,
) -> Result<()> {
    INPUTS.put(&vault.store, wtxn, &input.digest(), &input.encode())
}

/// The input kept under `digest`, when it decodes.
pub(crate) fn held_input_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<RelayedInput>> {
    Ok(INPUTS
        .get(store, txn, digest)?
        .and_then(|bytes| RelayedInput::decode(&bytes)))
}

/// Forgets the input kept under `digest`.
pub(crate) fn drop_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    INPUTS.delete(&vault.store, wtxn, digest).map(drop)
}

/// Forgets every input kept for a request on record `id`: a revoke leaves no
/// pending input of it (CALLS CUSTODY_REVOKE_ERASE). Returns how many it
/// forgot.
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
        .map(|(digest, _)| digest)
        .collect();
    for digest in &doomed {
        drop_input_in_txn(vault, wtxn, digest)?;
    }
    Ok(doomed.len())
}

/// Every input this vault keeps, by digest, as stored.
#[cfg(feature = "sync")]
pub(crate) fn held_inputs(vault: &Vault) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    INPUTS.scan(&vault.store, &rtxn)
}

impl Vault {
    /// Forgets every kept input whose request is answered, is on a secret an
    /// admitted revoke ended, or that this install folds as no admitted
    /// request at all: what remains is the relay of work still awaiting its
    /// holder. The owner work drain runs it beside the revoke settle.
    /// Returns how many it forgot.
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
                .map(|(digest, _)| digest)
                .collect()
        };
        if done.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|txn| {
            for digest in &done {
                drop_input_in_txn(self, txn, digest)?;
            }
            Ok(done.len())
        })
    }
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("{reason}; nothing was written"))
}
