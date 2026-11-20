use oneiron_crypto::HybridSecretKey;

use super::super::super::codec::{decode_register_input, encode_register_input};
use super::super::super::types::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus,
};
use super::envelopes::{fits_one, frame_envelope_count_for_test};
#[cfg(feature = "sync")]
use super::{INPUTS, RelayedInput, input_digest, keep_input_in_txn, kept_input_in_txn, part_key};
use super::{InputBinding, refused};
#[cfg(feature = "sync")]
use crate::Vault;
use crate::authority::{CustodyChange, CustodyPermitSet, CustodyRecipientPermit};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::world_keys::MachineSecret;

/// The vault id a test numbered input binds.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_VAULT_ID: [u8; 32] = [0x51; 32];
/// The custody revision a test numbered input binds as seen.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_SEEN: [u8; 32] = [0x53; 32];
/// The generation a test numbered input approves.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_GENERATION: u32 = 7;
/// The second a test numbered input is sealed at.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_AT: u64 = 1_780_000_000;
/// The request hash a kept test numbered input is stored under beside.
#[cfg(all(oneiron_test_support, feature = "sync"))]
const NUMBERED_TEST_REQUEST: [u8; 32] = [0x61; 32];

/// The secret id a test numbered input binds.
#[cfg(oneiron_test_support)]
fn numbered_test_id() -> EntityId {
    EntityId::from_bytes_unchecked([0x52; 16])
}

/// A portable record of `name` holding `value`, as a door seals it.
#[cfg(oneiron_test_support)]
fn numbered_test_record(name: &str, value: &[u8]) -> SecretCustodyRecord {
    SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        model_reveal_allowed: true,
        value_bytes: value.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: NUMBERED_TEST_AT,
        rotated_at: None,
        rotation_generation: NUMBERED_TEST_GENERATION,
        bindings: Vec::new(),
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    }
}

/// The exact permit a test numbered input binds for its holder.
#[cfg(oneiron_test_support)]
fn numbered_test_permits(holder: EntityId) -> CustodyPermitSet {
    let permits = [CustodyRecipientPermit {
        machine: holder,
        profile: [0x54; 32],
        encryption_key: [0x55; 32],
    }];
    CustodyPermitSet::from(&permits[..])
}

/// The binding a test numbered register input seals and opens under.
#[cfg(oneiron_test_support)]
fn numbered_test_binding(holder: EntityId, permits: &CustodyPermitSet) -> InputBinding<'_> {
    InputBinding {
        vault_id: NUMBERED_TEST_VAULT_ID,
        id: numbered_test_id(),
        change: CustodyChange::Register,
        generation: NUMBERED_TEST_GENERATION,
        seen: NUMBERED_TEST_SEEN,
        holder,
        permits,
    }
}

/// The holder's secret: its machine with the key `seed` names.
#[cfg(oneiron_test_support)]
fn numbered_test_secret(holder: EntityId, seed: u8) -> MachineSecret {
    MachineSecret {
        machine: holder,
        secret: HybridSecretKey::from_seeds(&[seed; 64], &[seed; 32]),
    }
}

/// Seals a register of `name` holding `value`, framed with `manifest`, to
/// `holder`'s key under the test binding, as a door seals it (FIX 5521),
/// for `test_doors::custody_numbered_input` (FIX 5624). Returns the sealed
/// frame, the body length it seals and the frame's envelope count.
///
/// # Errors
/// A body that fits one envelope, so the test seals nothing numbered; a
/// seal that fails; a sealed frame that states no envelope count.
#[cfg(oneiron_test_support)]
pub(crate) fn seal_numbered_register_for_test(
    holder: EntityId,
    seed: u8,
    name: &str,
    value: &[u8],
    manifest: Option<&str>,
) -> Result<(Vec<u8>, usize, u32)> {
    let record = numbered_test_record(name, value);
    let body = encode_register_input(&record, manifest)?;
    if fits_one(&body) {
        return Err(refused(
            "the test body fits one envelope; grow it past one envelope's bound",
        ));
    }
    let permits = numbered_test_permits(holder);
    let binding = numbered_test_binding(holder, &permits);
    let secret = HybridSecretKey::from_seeds(&[seed; 64], &[seed; 32]);
    let frame = binding.seal(secret.public_key(), &body)?;
    let count = frame_envelope_count_for_test(&frame)
        .ok_or_else(|| refused("a sealed numbered input states no envelope count"))?;
    Ok((frame, body.len(), count))
}

/// Opens `frame` with the holder's secret under the test binding, for
/// `test_doors::custody_numbered_input` (FIX 5624): the register's value,
/// framed manifest text and name. `None` when it does not open, or not to
/// a register body: the arm the executor refuses as `InvalidInput`.
#[cfg(oneiron_test_support)]
pub(crate) fn open_numbered_as_holder_for_test(
    frame: &[u8],
    holder: EntityId,
    seed: u8,
) -> Option<(Vec<u8>, Option<String>, String)> {
    let permits = numbered_test_permits(holder);
    let binding = numbered_test_binding(holder, &permits);
    let secret = numbered_test_secret(holder, seed);
    let body = binding.open(frame, frame.len() as u64, &secret)?;
    let (record, manifest) = decode_register_input(&body)?;
    Some((record.value_bytes, manifest, record.name))
}

/// What opening a kept test numbered input found.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) enum KeptNumberedOpen {
    /// No whole row, or no complete part list, is kept: the request stays
    /// pending.
    Missing,
    /// The kept rows do not open under the holder's key and binding, or not
    /// to a register body: the arm the executor refuses as `InvalidInput`.
    Invalid,
    /// The register's value, framed manifest text and name.
    Opened(Vec<u8>, Option<String>, String),
}

/// Keeps `frame` as the test input the digest the request would name,
/// whole or in numbered parts, for `test_doors::custody_numbered_input`
/// (FIX 5624). Returns that digest and how many rows keep it.
///
/// # Errors
/// A frame past the part list's bound; storage errors.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) fn keep_numbered_input_for_test(vault: &Vault, frame: &[u8]) -> Result<([u8; 32], u32)> {
    let row = RelayedInput {
        sealed_at: NUMBERED_TEST_AT,
        request: NUMBERED_TEST_REQUEST,
        witness: vec![0x62; 64],
        part: None,
        envelope: frame.to_vec(),
    };
    vault.with_write_txn(|wtxn| keep_input_in_txn(vault, wtxn, &row))?;
    let digest = input_digest(frame);
    let txn = vault.store.env.read_txn()?;
    let mut parts = 0_u32;
    for (_, bytes) in INPUTS.scan(&vault.store, &txn)? {
        if RelayedInput::decode(&bytes).is_some_and(|kept| kept.digest() == digest) {
            parts += 1;
        }
    }
    Ok((digest, parts))
}

/// Opens the test input kept under `digest` with the holder's secret under
/// the test binding, for `test_doors::custody_numbered_input` (FIX 5624).
///
/// # Errors
/// Storage errors reading a kept row.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) fn open_kept_numbered_for_test(
    vault: &Vault,
    digest: &[u8; 32],
    holder: EntityId,
    seed: u8,
) -> Result<KeptNumberedOpen> {
    let permits = numbered_test_permits(holder);
    let binding = numbered_test_binding(holder, &permits);
    let secret = numbered_test_secret(holder, seed);
    let txn = vault.store.env.read_txn()?;
    let Some(kept) = kept_input_in_txn(&vault.store, &txn, digest)? else {
        return Ok(KeptNumberedOpen::Missing);
    };
    let Some((body, _attached)) = kept.open(&binding, &secret)? else {
        return Ok(KeptNumberedOpen::Invalid);
    };
    let Some((record, manifest)) = decode_register_input(&body) else {
        return Ok(KeptNumberedOpen::Invalid);
    };
    Ok(KeptNumberedOpen::Opened(
        record.value_bytes,
        manifest,
        record.name,
    ))
}

/// Forgets part `index` of the test input kept under `digest`, for
/// `test_doors::custody_numbered_input` (FIX 5624). Returns whether a row
/// was kept there.
///
/// # Errors
/// Storage errors.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) fn drop_kept_numbered_part_for_test(
    vault: &Vault,
    digest: &[u8; 32],
    index: u32,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        let key = part_key(digest, index);
        let kept = INPUTS.get(&vault.store, wtxn, &key)?.is_some();
        INPUTS.delete(&vault.store, wtxn, &key)?;
        Ok(kept)
    })
}
