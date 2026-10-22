//! A relayed custody input's witness in numbered parts (FIX 8088).
//!
//! An input row carries its request's signed entry as its witness (FIX
//! 4996). A witness that fits one row's bound rides inline, as every input
//! accepted before did. One past it, a request permitting very many
//! recipients, travels as numbered witness rows of their own instead, each
//! at most [`CUSTODY_WITNESS_PART_BYTES`], beside the input's own rows: each
//! names the request, the input digest it names, a commitment to the whole
//! witness, its sealing second, its place, the part count and its bytes'
//! digest, signed by the request's own signer, so each row authenticates on
//! its own, under a key of its own. Each input row then carries, in place of
//! the whole, a reference to that group signed the same way over the row's
//! own place and bytes. Nothing waits on arrival order: the holder joins
//! every part, in order and count, checks the commitment, and requires the
//! whole to be the canonical signed request that names this input and was
//! signed by the parts' signer, before any custody effect; while a part is
//! missing or anything does not prove, the request stays pending, never an
//! invalid input. No total size, count or time bounds a witness.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::{INPUTS, MAX_INPUT_BYTES, RelayedInput, held_input_in_txn, part_key};
use crate::Vault;
use crate::authority::{
    AuthorityEntryHash, AuthorityKey, AuthorityOp, OwnerWorkBody, authority_entry_hash,
    decode_authority_log_entry_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// How a custody input's witness past one row travels (CALLS `8088 input
/// witness form`, Engine 10-22 05:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyInputWitnessForm {
    /// As numbered parts each signed by the request's signer and
    /// authenticated on its own, every input row with a signed reference to
    /// them, and the canonical whole verified at the holder before any
    /// effect. A witness that fits one row stays inline.
    SignerSignedNumberedParts,
}

const CUSTODY_INPUT_WITNESS_FORM: CustodyInputWitnessForm =
    CustodyInputWitnessForm::SignerSignedNumberedParts;

/// The most bytes of a witness one part carries (CALLS `8088 input witness
/// form`): an input row's own bound, a codec floor, never a bound on the
/// whole witness.
pub(crate) const CUSTODY_WITNESS_PART_BYTES: usize = MAX_INPUT_BYTES;

const PART_LABEL: &[u8] = b"oneiron/custody-input-witness-part/v1\0";
const REF_LABEL: &[u8] = b"oneiron/custody-input-witness-ref/v1\0";
const SIGN_DOMAIN: &[u8] = b"oneiron/custody-input-witness-sig/v1\0";
const KEY_DOMAIN: &[u8] = b"oneiron/custody-input-witness-part-key/v1";
const COMMIT_DOMAIN: &[u8] = b"oneiron/custody-input-witness-commitment/v1";
const FRAGMENT_DOMAIN: &[u8] = b"oneiron/custody-input-witness-fragment/v1";
const ROW_DOMAIN: &[u8] = b"oneiron/custody-input-witness-row/v1";
/// What a signature is over: a witness part, or an input row's reference.
const KIND_PART: u8 = 0;
const KIND_INPUT: u8 = 1;
/// A whole input row's place: it is no part.
const WHOLE_ROW: u32 = u32::MAX;
/// A witness part's frame after its label: its sealing second, the
/// request, the input digest, the commitment, the count, the signer, its
/// place and its signature.
const PART_FRAME_BYTES: usize = 8 + 32 + 32 + 32 + 4 + 32 + 4 + 64;
/// A reference after its label: the commitment, the count, the signer and
/// its signature.
const REF_BYTES: usize = 32 + 4 + 32 + 64;

/// Each witness part this vault keeps to relay, or keeps as its holder
/// until the request is answered, by its own key.
const WITNESSES: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_WITNESS);

/// What every row of one witness binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WitnessGroup {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The input digest the request names.
    pub(crate) input: [u8; 32],
    commitment: [u8; 32],
    count: u32,
    signer: [u8; 32],
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

impl WitnessGroup {
    /// What a signature of a `kind` row at `place`, over bytes `digest`,
    /// covers.
    fn transcript(&self, kind: u8, place: u32, digest: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGN_DOMAIN.len() + 1 + 8 + 32 * 5 + 8);
        out.extend_from_slice(SIGN_DOMAIN);
        out.push(kind);
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.input);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&place.to_be_bytes());
        out.extend_from_slice(digest);
        out
    }

    fn sign(&self, signing: &SigningKey, kind: u8, place: u32, digest: &[u8; 32]) -> [u8; 64] {
        signing
            .sign(&self.transcript(kind, place, digest))
            .to_bytes()
    }

    fn verifies(&self, kind: u8, place: u32, digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(&self.signer).is_ok_and(|key| {
            key.verify_strict(
                &self.transcript(kind, place, digest),
                &Signature::from_bytes(signature),
            )
            .is_ok()
        })
    }

    /// Whether `signer` is the key this witness names as its signer.
    #[cfg(feature = "sync")]
    pub(crate) fn signed_by(&self, signer: &[u8; 32]) -> bool {
        self.signer == *signer
    }

    /// The key part `index` of this witness is kept and relayed under.
    fn part_key(&self, index: u32) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_DOMAIN);
        hasher.update(&self.request);
        hasher.update(&self.input);
        hasher.update(&self.commitment);
        hasher.update(&index.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// One numbered part of a witness.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WitnessPart {
    pub(crate) group: WitnessGroup,
    index: u32,
    signature: [u8; 64],
    fragment: Vec<u8>,
}

// Never print the request's bytes.
impl std::fmt::Debug for WitnessPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessPart")
            .field("index", &self.index)
            .field("count", &self.group.count)
            .field("bytes", &self.fragment.len())
            .finish_non_exhaustive()
    }
}

/// Reads `N` bytes off the front of `bytes`.
fn take<'a, const N: usize>(bytes: &mut &'a [u8]) -> Option<&'a [u8; N]> {
    let (head, rest) = bytes.split_first_chunk::<N>()?;
    *bytes = rest;
    Some(head)
}

impl WitnessPart {
    /// The label, the frame, then the part's bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PART_LABEL.len() + PART_FRAME_BYTES + self.fragment.len());
        out.extend_from_slice(PART_LABEL);
        out.extend_from_slice(&self.group.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.group.request);
        out.extend_from_slice(&self.group.input);
        out.extend_from_slice(&self.group.commitment);
        out.extend_from_slice(&self.group.count.to_be_bytes());
        out.extend_from_slice(&self.group.signer);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.fragment);
        out
    }

    /// Decodes a witness part strictly; `None` for another label, a short
    /// frame, a zero request, a count of none, a place outside its count,
    /// or bytes empty or past [`CUSTODY_WITNESS_PART_BYTES`]. Its signature
    /// is read, not judged: [`Self::authenticated`] judges it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut rest = bytes.strip_prefix(PART_LABEL)?;
        let sealed_at = u64::from_be_bytes(*take::<8>(&mut rest)?);
        let request = *take::<32>(&mut rest)?;
        let input = *take::<32>(&mut rest)?;
        let commitment = *take::<32>(&mut rest)?;
        let count = u32::from_be_bytes(*take::<4>(&mut rest)?);
        let signer = *take::<32>(&mut rest)?;
        let index = u32::from_be_bytes(*take::<4>(&mut rest)?);
        let signature = *take::<64>(&mut rest)?;
        if request == [0; 32]
            || count == 0
            || index >= count
            || rest.is_empty()
            || rest.len() > CUSTODY_WITNESS_PART_BYTES
        {
            return None;
        }
        Some(Self {
            group: WitnessGroup {
                sealed_at,
                request,
                input,
                commitment,
                count,
                signer,
            },
            index,
            signature,
            fragment: rest.to_vec(),
        })
    }

    /// Whether its signature verifies, by the signer it names, over its own
    /// frame and bytes: it authenticates without any sibling.
    pub(crate) fn authenticated(&self) -> bool {
        self.group.verifies(
            KIND_PART,
            self.index,
            &digest(FRAGMENT_DOMAIN, &self.fragment),
            &self.signature,
        )
    }

    /// The key it is kept and relayed under.
    pub(crate) fn row_key(&self) -> [u8; 32] {
        self.group.part_key(self.index)
    }
}

impl RelayedInput {
    /// This row's place in its input: its part's index, or none.
    fn place(&self) -> u32 {
        self.part.as_ref().map_or(WHOLE_ROW, |part| part.index)
    }

    /// The witness group this row's signed reference names, when its
    /// witness travels in parts and the reference verifies, by the signer
    /// it names, over this row's sealing second, request, digest, place and
    /// bytes (FIX 8088): the row authenticates without any sibling. `None`
    /// for an inline witness, or a reference that does not verify.
    pub(crate) fn witness_group(&self) -> Option<WitnessGroup> {
        let mut rest = self.witness.strip_prefix(REF_LABEL)?;
        if rest.len() != REF_BYTES {
            return None;
        }
        let commitment = *take::<32>(&mut rest)?;
        let count = u32::from_be_bytes(*take::<4>(&mut rest)?);
        let signer = *take::<32>(&mut rest)?;
        let signature = *take::<64>(&mut rest)?;
        let group = WitnessGroup {
            sealed_at: self.sealed_at,
            request: self.request,
            input: self.digest(),
            commitment,
            count,
            signer,
        };
        (count > 0
            && group.verifies(
                KIND_INPUT,
                self.place(),
                &digest(ROW_DOMAIN, &self.envelope),
                &signature,
            ))
        .then_some(group)
    }

    /// Whether this row's witness travels in parts.
    pub(crate) fn references_witness(&self) -> bool {
        self.witness.starts_with(REF_LABEL)
    }

    /// The reference to `group` this row carries, signed with `signing`.
    fn reference(&self, group: &WitnessGroup, signing: &SigningKey) -> Vec<u8> {
        let signature = group.sign(
            signing,
            KIND_INPUT,
            self.place(),
            &digest(ROW_DOMAIN, &self.envelope),
        );
        let mut out = Vec::with_capacity(REF_LABEL.len() + REF_BYTES);
        out.extend_from_slice(REF_LABEL);
        out.extend_from_slice(&group.commitment);
        out.extend_from_slice(&group.count.to_be_bytes());
        out.extend_from_slice(&group.signer);
        out.extend_from_slice(&signature);
        out
    }
}

/// Keeps `input`, whose witness is its request's whole signed entry, as
/// [`super::keep_input_in_txn`] does. A witness past one row's bound
/// travels in numbered parts instead, each signed with `signing`, the key
/// that signed the request, and each input row carries a signed reference to
/// them (FIX 8088). A request another key signed keeps today's inline form.
pub(crate) fn keep_witnessed_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut input: RelayedInput,
    signing: &SigningKey,
) -> Result<()> {
    match CUSTODY_INPUT_WITNESS_FORM {
        CustodyInputWitnessForm::SignerSignedNumberedParts => {}
    }
    let signer = signing.verifying_key().to_bytes();
    let signed = input.witness.len() > MAX_INPUT_BYTES
        && decode_authority_log_entry_body(&input.witness).is_ok_and(
            |entry| matches!(entry.signer_key(), AuthorityKey::Ed25519(key) if *key == signer),
        );
    if !signed {
        return super::keep_input_in_txn(vault, wtxn, &input);
    }
    let witness = std::mem::take(&mut input.witness);
    let count =
        u32::try_from(witness.len().div_ceil(CUSTODY_WITNESS_PART_BYTES)).map_err(|_| {
            Error::InvalidConfig("a custody witness past its part count's codec".into())
        })?;
    let group = WitnessGroup {
        sealed_at: input.sealed_at,
        request: input.request,
        input: input.digest(),
        commitment: digest(COMMIT_DOMAIN, &witness),
        count,
        signer,
    };
    for (index, fragment) in (0_u32..).zip(witness.chunks(CUSTODY_WITNESS_PART_BYTES)) {
        let part = WitnessPart {
            group,
            index,
            signature: group.sign(
                signing,
                KIND_PART,
                index,
                &digest(FRAGMENT_DOMAIN, fragment),
            ),
            fragment: fragment.to_vec(),
        };
        WITNESSES.put(&vault.store, wtxn, &part.row_key(), &part.encode())?;
    }
    let rows = match input.parts()? {
        Some(parts) => parts,
        None => vec![input],
    };
    for mut row in rows {
        row.witness = row.reference(&group, signing);
        INPUTS.put(&vault.store, wtxn, &row.row_key(), &row.encode())?;
    }
    Ok(())
}

/// What the holder's join of an input's witness found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessJoin {
    /// Every row carries its witness inline: nothing more to join.
    Inline,
    /// Every part is here and the whole proves the request.
    Verified,
    /// A part is missing, or something does not prove yet: pending.
    Missing,
}

/// Joins the witness of the input the request names `digest` of, as this
/// vault keeps it (FIX 8088): every input row inline is [`WitnessJoin::Inline`].
/// Otherwise every row's reference must name one group, every part of it
/// must be here, authenticated, in order and count, the whole must match
/// its commitment and be the canonical signed request entry that hashes to
/// the request, names `digest` and was signed by the parts' signer.
/// Anything short of that is [`WitnessJoin::Missing`]: the request stays
/// pending, never an invalid input.
pub(crate) fn witness_joined_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest_named: &[u8; 32],
) -> Result<WitnessJoin> {
    let mut rows = Vec::new();
    match held_input_in_txn(store, txn, digest_named)? {
        Some(whole) if whole.part.is_none() => rows.push(whole),
        _ => {
            let mut index = 0_u32;
            while let Some(row) = held_input_in_txn(store, txn, &part_key(digest_named, index))? {
                let count = row.part.as_ref().map_or(0, |part| part.digests.len());
                rows.push(row);
                index = index.saturating_add(1);
                if usize::try_from(index).map_or(true, |done| done >= count) {
                    break;
                }
            }
        }
    }
    if rows.is_empty() {
        return Ok(WitnessJoin::Missing);
    }
    if rows.iter().all(|row| !row.references_witness()) {
        return Ok(WitnessJoin::Inline);
    }
    let mut groups = rows.iter().map(RelayedInput::witness_group);
    let Some(Some(group)) = groups.next() else {
        return Ok(WitnessJoin::Missing);
    };
    if groups.any(|other| other != Some(group)) || group.input != *digest_named {
        return Ok(WitnessJoin::Missing);
    }
    let mut whole = Vec::new();
    for index in 0..group.count {
        let Some(part) = WITNESSES
            .get(store, txn, &group.part_key(index))?
            .and_then(|bytes| WitnessPart::decode(&bytes))
        else {
            return Ok(WitnessJoin::Missing);
        };
        if part.group != group || part.index != index || !part.authenticated() {
            return Ok(WitnessJoin::Missing);
        }
        whole.extend_from_slice(&part.fragment);
    }
    if digest(COMMIT_DOMAIN, &whole) != group.commitment {
        return Ok(WitnessJoin::Missing);
    }
    let proves = decode_authority_log_entry_body(&whole).is_ok_and(|entry| {
        authority_entry_hash(&entry).is_ok_and(|hash| hash == group.request)
            && matches!(entry.signer_key(), AuthorityKey::Ed25519(key) if *key == group.signer)
            && matches!(
                &entry.op,
                AuthorityOp::OwnerWorkRequest(request)
                    if matches!(&request.work, OwnerWorkBody::Custody { input: Some(named), .. } if named == digest_named)
            )
    });
    Ok(if proves {
        WitnessJoin::Verified
    } else {
        WitnessJoin::Missing
    })
}

/// The witness part kept under `key`, when it decodes.
#[cfg(feature = "sync")]
pub(crate) fn held_witness_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<WitnessPart>> {
    Ok(WITNESSES
        .get(store, txn, key)?
        .and_then(|bytes| WitnessPart::decode(&bytes)))
}

/// Keeps `part` in `wtxn` under its own key.
#[cfg(feature = "sync")]
pub(crate) fn keep_witness_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    part: &WitnessPart,
) -> Result<()> {
    WITNESSES.put(&vault.store, wtxn, &part.row_key(), &part.encode())
}

/// Every witness part this vault keeps, by its key, as stored.
#[cfg(feature = "sync")]
pub(crate) fn held_witnesses(vault: &Vault) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    WITNESSES.scan(&vault.store, &rtxn)
}

/// The keys of the rows of `table` in `txn` whose bytes `pick` takes, read
/// leniently: a key not of its width is left for its settle.
fn picked_keys(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    table: &SideTable<[u8; 32], Vec<u8>, Raw>,
    pick: impl Fn(&[u8]) -> bool,
) -> Result<Vec<[u8; 32]>> {
    let mut keys = Vec::new();
    for row in table.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        if let Ok(key) = <[u8; 32]>::try_from(key.as_slice())
            && pick(&bytes)
        {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Forgets every input row kept for the input the request names `digest`
/// of, whatever part of it is here, a first part missing or a late part
/// included, and every witness part of it.
pub(crate) fn drop_rows_of_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest_named: &[u8; 32],
) -> Result<()> {
    let inputs = picked_keys(&vault.store, wtxn, &INPUTS, |bytes| {
        RelayedInput::decode(bytes).is_some_and(|input| input.digest() == *digest_named)
    })?;
    for key in &inputs {
        INPUTS.delete(&vault.store, wtxn, key)?;
    }
    drop_witnesses_in_txn(vault, wtxn, |group| group.input == *digest_named)?;
    Ok(())
}

/// Forgets every witness part whose group `doomed` names; one that does not
/// decode stays for the settle below. Returns how many it forgot.
pub(crate) fn drop_witnesses_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doomed: impl Fn(&WitnessGroup) -> bool,
) -> Result<usize> {
    let keys = picked_keys(&vault.store, wtxn, &WITNESSES, |bytes| {
        WitnessPart::decode(bytes).is_some_and(|part| doomed(&part.group))
    })?;
    for key in &keys {
        WITNESSES.delete(&vault.store, wtxn, key)?;
    }
    Ok(keys.len())
}

/// The keys of every witness part `done` holds done, or that does not
/// decode, as the settle of kept inputs forgets theirs.
pub(crate) fn settled_witnesses_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    done: impl Fn(&AuthorityEntryHash) -> bool,
) -> Result<Vec<[u8; 32]>> {
    picked_keys(store, txn, &WITNESSES, |bytes| {
        WitnessPart::decode(bytes).is_none_or(|part| done(&part.group.request))
    })
}

/// Forgets the witness parts kept under `keys`.
pub(crate) fn delete_witnesses_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    keys: &[[u8; 32]],
) -> Result<()> {
    for key in keys {
        WITNESSES.delete(&vault.store, wtxn, key)?;
    }
    Ok(())
}

/// The record a witness part's request is on, by `fold`: for a revoke's
/// cleanup of every row kept for a request on that record.
pub(crate) fn witness_target(
    fold: &crate::authority::AuthorityFold,
    group: &WitnessGroup,
) -> Option<EntityId> {
    fold.owner_work_request(&group.request)
        .map(|request| request.act.target)
}
