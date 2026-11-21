//! Peer-signed setting acts for the Setting primitive's tests: enrolled peer machines,
//! frontiers, and the landing and signing of their acts, beside rows, copies, and pack
//! heads beside the live log.

use super::*;

/// Another machine of the vault's owner (stage 7a-2): enrolled as the owner's own, its install
/// key held by the test, so it signs setting acts as its own door would.
#[cfg(feature = "test-support")]
pub struct EnrolledMachine {
    machine: EntityId,
    key: ed25519_dalek::SigningKey,
}

#[cfg(feature = "test-support")]
impl EnrolledMachine {
    /// The machine's MACHINE row: the carrier its acts name.
    #[must_use]
    pub fn machine(&self) -> EntityId {
        self.machine
    }
}

/// Enrols a machine whose install key is derived from `seed` as one of the owner's own
/// machines, by the owner's answer on this install.
///
/// # Errors
///
/// A vault with no authority root; the enrolment's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn enroll_machine_with_key(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: u8,
) -> Result<EnrolledMachine> {
    use crate::authority::{
        ActSurface, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
        MachineRole, machine_profile_proof_transcript,
    };
    use ed25519_dalek::Signer;

    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let machine = EntityId::now();
    let vault_id = vault
        .authority_vault_id()?
        .ok_or(Error::InvariantViolation(
            "a peer machine needs a rooted vault",
        ))?;
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = key
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    vault.enroll_machine(
        owner,
        ActSurface::ThisInstall,
        &MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
            restored_from: None,
        },
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    Ok(EnrolledMachine { machine, key })
}

/// Where the acts on `key`'s row (`item`, `mode`, `scope`) stand now: an act a peer signs on
/// it later did not see any act appended since.
#[cfg(feature = "test-support")]
pub struct SettingFrontier(crate::authority::SettingFrontier);

/// The frontier of `key`'s row `mode` at `scope`, for `item`.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_frontier(
    vault: &Vault,
    key: &str,
    item: Option<&str>,
    mode: SettingMode,
    scope: SettingScope,
) -> Result<SettingFrontier> {
    vault
        .setting_frontier(&[row_key(key, item, mode, scope)])
        .map(SettingFrontier)
}

/// One setting row as a test names it: its key, item, mode and scope.
#[cfg(feature = "test-support")]
pub type SlotName<'a> = (&'a str, Option<&'a str>, SettingMode, SettingScope);

/// The frontier of the rows `slots` together (stage 7a-3): a batch signed on it names each row's
/// revision as it stood.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_frontier_of(vault: &Vault, slots: &[SlotName<'_>]) -> Result<SettingFrontier> {
    let slots: Vec<_> = slots
        .iter()
        .map(|(key, item, mode, scope)| row_key(key, *item, *mode, scope.clone()))
        .collect();
    vault.setting_frontier(&slots).map(SettingFrontier)
}

#[cfg(feature = "test-support")]
fn row_key(
    key: &str,
    item: Option<&str>,
    mode: SettingMode,
    scope: SettingScope,
) -> oneiron_setting_contract::RowKey {
    oneiron_setting_contract::RowKey {
        name: key.to_owned(),
        item: item.map(str::to_owned),
        mode,
        scope,
    }
}

/// The owner `owner`'s change of `key`'s row (`item`, `mode`, `scope`) to `value` (`None`
/// clears), as `signer`'s own door signs it on `frontier` at `ts`, landed here as a peer's entry
/// lands: through the authority log's write door, whose commit runs the setting projection.
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_act_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    owner: EntityId,
    frontier: &SettingFrontier,
    (key, item, mode, scope): (&str, Option<&str>, SettingMode, SettingScope),
    value: Option<serde_json::Value>,
    ts: u64,
) -> Result<()> {
    land_setting_batch_from(
        vault,
        signer,
        owner,
        frontier,
        &[((key, item, mode, scope), value)],
        ts,
    )
    .map(|_| ())
}

/// The owner `owner`'s change of each row of `rows` to its value (`None` clears) as ONE act
/// (a batch, stage 7a-3), signed as `signer`'s own door signs it on `frontier` at `ts`, landed
/// here as a peer's entry lands. A row `frontier` did not read names `seen` zero. Whether the
/// fold here counts the entry (valid, and not held back).
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_batch_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    owner: EntityId,
    frontier: &SettingFrontier,
    rows: &[(SlotName<'_>, Option<serde_json::Value>)],
    ts: u64,
) -> Result<bool> {
    let rows = rows
        .iter()
        .map(|((key, item, mode, scope), value)| {
            let value = match value {
                Some(value) => crate::authority::SlotValue::Inline(json_bytes(value)?),
                None => crate::authority::SlotValue::Clear,
            };
            Ok((row_key(key, *item, *mode, scope.clone()), value))
        })
        .collect::<Result<Vec<_>>>()?;
    land_slot_values_from(vault, (signer, owner), frontier, rows, ts)
}

/// `rows`, as `signer`'s own door signs them for the owner `owner` on `frontier` at `ts`, landed
/// here as a peer's entry lands. Whether the fold here counts the entry.
#[cfg(feature = "test-support")]
fn land_slot_values_from(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    rows: Vec<(
        oneiron_setting_contract::RowKey,
        crate::authority::SlotValue,
    )>,
    ts: u64,
) -> Result<bool> {
    let entry =
        vault.sign_setting_act_as((signer.machine, &signer.key), owner, &frontier.0, rows, ts)?;
    let hash = oneiron_authority::authority::authority_entry_hash(&entry)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(entry, at, ts)])?;
    let fold = vault.authority_fold()?;
    Ok(fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash))
}

/// A setting value's JSON bytes, as a door writes them.
#[cfg(feature = "test-support")]
fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::InvariantViolation("a setting value's JSON"))
}

/// The owner `owner`'s change of the row `slot` to `value` with its value beside the act (stage
/// 7c-1): the act keeps only BLAKE3 over the value's JSON bytes, as `signer`'s own door signs it
/// on `frontier` at `ts`, landed here as a peer's entry lands, without the row that holds the
/// value ([`land_setting_beside_value`] lands that). Whether the fold here counts the entry.
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_act_from(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
    ts: u64,
) -> Result<bool> {
    let digest = oneiron_authority::authority::setting_value_digest(&json_bytes(value)?);
    let rows = vec![(
        row_key(key, item, mode, scope),
        crate::authority::SlotValue::Beside(digest),
    )];
    land_slot_values_from(vault, (signer, owner), frontier, rows, ts)
}

/// The owner `owner`'s change of the row `slot` to `value` with its value beside the act (stage
/// 7c-1), as `signer`'s own door signs it on `frontier` at `ts`, not landed: a test lands the row
/// that holds the value, which the act names, before the act ([`land_setting_beside_value_before`],
/// [`land_signed_setting_act`]).
///
/// # Errors
///
/// A key name of another shape; a value with no JSON; storage errors.
#[cfg(feature = "test-support")]
pub fn sign_setting_beside_act_from(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
    ts: u64,
) -> Result<SignedSettingAct> {
    let digest = oneiron_authority::authority::setting_value_digest(&json_bytes(value)?);
    let rows = vec![(
        row_key(key, item, mode, scope),
        crate::authority::SlotValue::Beside(digest),
    )];
    vault
        .sign_setting_act_as((signer.machine, &signer.key), owner, &frontier.0, rows, ts)
        .map(SignedSettingAct)
}

/// The ASSET row that holds `value` beside the live act on the row `slot` that keeps only its
/// digest (stage 7c-1).
///
/// # Errors
///
/// No such live act; a key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_beside_row(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
) -> Result<EntityId> {
    crate::setting::beside_row_of(vault, &row_key(key, item, mode, scope), &json_bytes(value)?)
}

/// Lands the row that holds `value` beside the live act on the row `slot`, in a write of its own,
/// as a peer's row lands: through the batch door, whose commit runs the setting projection
/// (stage 7c-1).
///
/// # Errors
///
/// No such live act; the put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_value(
    vault: &Vault,
    slot: SlotName<'_>,
    value: &serde_json::Value,
) -> Result<()> {
    land_setting_beside_value_holding(vault, slot, value, value)
}

/// Lands at the row for `value` beside the live act on the row `slot` a row that holds `held`'s
/// JSON bytes: a row that does not match its digest where `held` is another value (stage 7c-1).
///
/// # Errors
///
/// No such live act; the put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_value_holding(
    vault: &Vault,
    slot: SlotName<'_>,
    value: &serde_json::Value,
    held: &serde_json::Value,
) -> Result<()> {
    let row = setting_beside_row(vault, slot, value)?;
    crate::setting::land_beside_row(vault, row, (&json_bytes(held)?, true))
}

/// Lands at the row for `value` beside the live act on the row `slot` a row whose body is
/// `body` alone, with no setting value's tag (stage 7c-1).
///
/// # Errors
///
/// No such live act; the put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_untagged(
    vault: &Vault,
    slot: SlotName<'_>,
    value: &serde_json::Value,
    body: &[u8],
) -> Result<()> {
    let row = setting_beside_row(vault, slot, value)?;
    crate::setting::land_beside_row(vault, row, (body, false))
}

/// Lands, before `act` itself, the row for `value` beside `act` on the row `slot`, holding
/// `held`'s JSON bytes (`value`'s, or another value's: a row that does not match its digest), in
/// a write of its own (stage 7c-1). The row's id.
///
/// # Errors
///
/// A key name of another shape; the put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_value_before(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
    (value, held): (&serde_json::Value, &serde_json::Value),
    act: &SignedSettingAct,
) -> Result<EntityId> {
    let row = crate::setting::beside_row_for(
        &row_key(key, item, mode, scope),
        &json_bytes(value)?,
        &act.hash()?,
    )?;
    crate::setting::land_beside_row(vault, row, (&json_bytes(held)?, true))?;
    Ok(row)
}

/// The JSON the row for `value` beside the live act on the row `slot` holds here; `None` when no
/// such row is readable here (stage 7c-1).
///
/// # Errors
///
/// No such live act; a row whose bytes are not JSON; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_beside_value_here(
    vault: &Vault,
    slot: SlotName<'_>,
    value: &serde_json::Value,
) -> Result<Option<serde_json::Value>> {
    crate::setting::beside_row_json(vault, setting_beside_row(vault, slot, value)?)?
        .map(|json| {
            serde_json::from_slice(&json)
                .map_err(|_| Error::InvariantViolation("a beside row's JSON"))
        })
        .transpose()
}

/// The live acts on `key`'s row (`item`, `mode`, `scope`), a move's copy among them (stage
/// 7a-4): what a copy of the row names. Empty when no act names the row.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_slot_heads(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
) -> Result<Vec<oneiron_authority::authority::AuthorityEntryHash>> {
    let target =
        oneiron_authority::authority::setting_slot_target(&row_key(key, item, mode, scope))?;
    let txn = vault.store.env.read_txn()?;
    vault.setting_slot_live_in_txn(&txn, target)
}

/// What the live copies on `key`'s row (`item`, `mode`, `scope`) name, each as its row's key and
/// scope and the act (stage 7c-3b: a birth names its source's heads). Empty when no copy is live
/// on the row.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_copy_names(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
) -> Result<
    Vec<(
        String,
        SettingScope,
        oneiron_authority::authority::AuthorityEntryHash,
    )>,
> {
    let target =
        oneiron_authority::authority::setting_slot_target(&row_key(key, item, mode, scope))?;
    let txn = vault.store.env.read_txn()?;
    let mut names = Vec::new();
    for act in vault.setting_slot_live_in_txn(&txn, target)? {
        if let Some(copy) = vault.setting_slot_head_in_txn(&txn, target, act)?.copy {
            names.extend(
                copy.names
                    .into_iter()
                    .map(|name| (name.slot.name, name.slot.scope, name.act)),
            );
        }
    }
    names.sort();
    Ok(names)
}

/// One carried row a copy lists, with the acts it names, each by its own row.
#[cfg(feature = "test-support")]
pub type CopiedRow<'a> = (
    SlotName<'a>,
    Vec<(
        SlotName<'a>,
        oneiron_authority::authority::AuthorityEntryHash,
    )>,
);

/// A move's copy of each carried row of `rows` (stage 7a-4), as `signer`'s own carry signs it on
/// `frontier` at `ts`, landed here as a peer's entry lands. A row `frontier` did not read names
/// `seen` zero. The entry's hash, and whether the fold here counts it (valid, and not held back).
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_copy_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    frontier: &SettingFrontier,
    rows: &[CopiedRow<'_>],
    ts: u64,
) -> Result<(oneiron_authority::authority::AuthorityEntryHash, bool)> {
    let rows = rows
        .iter()
        .map(|((key, item, mode, scope), names)| {
            let names = names
                .iter()
                .map(|((key, item, mode, scope), act)| {
                    oneiron_authority::authority::SettingCopyName {
                        slot: row_key(key, *item, *mode, scope.clone()),
                        act: *act,
                    }
                })
                .collect::<Vec<_>>();
            (row_key(key, *item, *mode, scope.clone()), names)
        })
        .collect::<Vec<_>>();
    let entry = vault.sign_setting_copy_as((signer.machine, &signer.key), &frontier.0, rows, ts)?;
    let hash = oneiron_authority::authority::authority_entry_hash(&entry)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(entry, at, ts)])?;
    let fold = vault.authority_fold()?;
    Ok((
        hash,
        fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash),
    ))
}

/// One setting act a peer signed that this install has not landed yet (stage 7b-3 tests).
#[cfg(feature = "test-support")]
pub struct SignedSettingAct(oneiron_authority::authority::AuthorityLogEntry);

#[cfg(feature = "test-support")]
impl SignedSettingAct {
    /// The act's entry hash, which names the row of a value beside it (stage 7c-1 tests).
    ///
    /// # Errors
    ///
    /// An entry that does not encode.
    pub fn hash(&self) -> Result<oneiron_authority::authority::AuthorityEntryHash> {
        Ok(oneiron_authority::authority::authority_entry_hash(&self.0)?)
    }
}

/// The owner `owner`'s change of the row `slot` to `value` (`None` clears), signed as `signer`'s
/// own door signs it on `frontier` at `ts`, `ahead` sequences past the signer's next one here,
/// and not landed ([`land_signed_setting_act`]). Landed before an act its signer signs after it
/// at the next sequence, it puts that act past the signer's sequence floor on this install,
/// which then counts that act restriction only (stage 7b-3 tests).
///
/// # Errors
///
/// A key name of another shape; a value with no JSON; storage errors.
#[cfg(feature = "test-support")]
pub fn sign_setting_act_ahead(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    ((key, item, mode, scope), value): (SlotName<'_>, Option<serde_json::Value>),
    (ts, ahead): (u64, u64),
) -> Result<SignedSettingAct> {
    let inline = value
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| Error::InvariantViolation("a setting value's JSON"))?;
    vault
        .sign_setting_act_ahead_as(
            (signer.machine, &signer.key),
            (owner, &frontier.0),
            vec![(row_key(key, item, mode, scope), inline)],
            (ts, ahead),
        )
        .map(SignedSettingAct)
}

/// Lands `act` here at `ts`, as a peer's entry lands (stage 7b-3 tests). The entry's hash.
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_signed_setting_act(
    vault: &Vault,
    act: &SignedSettingAct,
    ts: u64,
) -> Result<oneiron_authority::authority::AuthorityEntryHash> {
    let hash = oneiron_authority::authority::authority_entry_hash(&act.0)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(act.0.clone(), at, ts)])?;
    Ok(hash)
}

/// The frontier of `pack`'s head acts now (stage 7c-3a).
///
/// # Errors
///
/// A pack target that does not encode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_pack_frontier_of(vault: &Vault, pack: &str) -> Result<SettingFrontier> {
    vault.setting_pack_frontier(pack).map(SettingFrontier)
}

/// The frontier of the owner's yeses to defaults of `pack`'s table `digest` (64 hex digits) now
/// (stage 7c-3c).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; a target that does not encode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_pack_accept_frontier_of(
    vault: &Vault,
    (pack, digest): (&str, &str),
) -> Result<SettingFrontier> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    vault
        .setting_pack_accept_frontier(pack, &digest)
        .map(SettingFrontier)
}

/// A pack's head, as `signer`'s own pack door signs it on `frontier` at `ts`, landed here as a
/// peer's entry lands (stage 7c-3a). The digest is 64 hex digits. Whether the fold here counts
/// the entry (valid, and not held back).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; the log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_pack_head_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    frontier: &SettingFrontier,
    (pack, version, digest, held): (&str, &str, &str, &[&str]),
    ts: u64,
) -> Result<bool> {
    land_pack_head_from(
        vault,
        (signer, frontier),
        (pack, version, digest, held),
        None,
        ts,
    )
}

/// The owner `owner`'s yes to `pack`'s defaults `accepted` of the table `digest` names, decided
/// on `signer` and signed by its install key on `frontier` at `ts`, landed here as a peer's entry
/// lands (stage 7c-3c): one head act with his act, holding `held`. Whether the fold here counts
/// the entry (valid, and not held back).
///
/// # Errors
///
/// As [`land_setting_pack_head_from`].
#[cfg(feature = "test-support")]
pub fn land_setting_pack_accept_from(
    vault: &Vault,
    (signer, frontier): (&EnrolledMachine, &SettingFrontier),
    (pack, version, digest, held): (&str, &str, &str, &[&str]),
    (owner, accepted): (EntityId, &[&str]),
    ts: u64,
) -> Result<bool> {
    let accepted = accepted.iter().map(|name| (*name).to_owned()).collect();
    land_pack_head_from(
        vault,
        (signer, frontier),
        (pack, version, digest, held),
        Some((owner, accepted)),
        ts,
    )
}

#[cfg(feature = "test-support")]
fn land_pack_head_from(
    vault: &Vault,
    (signer, frontier): (&EnrolledMachine, &SettingFrontier),
    (pack, version, digest, held): (&str, &str, &str, &[&str]),
    accept: Option<(EntityId, Vec<String>)>,
    ts: u64,
) -> Result<bool> {
    let act = sign_pack_head_from(
        vault,
        (signer, frontier),
        (pack, version, digest, held),
        accept,
        ts,
    )?;
    land_signed_pack_act(vault, &act, ts)
}

/// The owner `owner`'s yes to `pack`'s defaults `accepted` of the table `digest` names, decided
/// on `signer` and signed by its install key on `frontier` at `ts`, holding `held`, and not
/// landed ([`land_signed_pack_act`]): a test lands the table's row beside it first, as a peer's
/// row can arrive before its act (stage 7c-3c review).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; storage errors.
#[cfg(feature = "test-support")]
pub fn sign_setting_pack_accept_from(
    vault: &Vault,
    (signer, frontier): (&EnrolledMachine, &SettingFrontier),
    (pack, version, digest, held): (&str, &str, &str, &[&str]),
    (owner, accepted): (EntityId, &[&str]),
    ts: u64,
) -> Result<SignedSettingAct> {
    let accepted = accepted.iter().map(|name| (*name).to_owned()).collect();
    sign_pack_head_from(
        vault,
        (signer, frontier),
        (pack, version, digest, held),
        Some((owner, accepted)),
        ts,
    )
}

#[cfg(feature = "test-support")]
fn sign_pack_head_from(
    vault: &Vault,
    (signer, frontier): (&EnrolledMachine, &SettingFrontier),
    (pack, version, digest, held): (&str, &str, &str, &[&str]),
    accept: Option<(EntityId, Vec<String>)>,
    ts: u64,
) -> Result<SignedSettingAct> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    let held = held.iter().map(|name| (*name).to_owned()).collect();
    vault
        .sign_setting_pack_head_as(
            (signer.machine, &signer.key),
            &frontier.0,
            (pack, version, digest, held),
            (accept, ts),
        )
        .map(SignedSettingAct)
}

/// Lands the pack act `act` (a head or the owner's yes) here at `ts`, as a peer's entry lands
/// (stage 7c-3c review). Whether the fold here counts the entry (valid, and not held back).
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_signed_pack_act(vault: &Vault, act: &SignedSettingAct, ts: u64) -> Result<bool> {
    let hash = land_signed_setting_act(vault, act, ts)?;
    let fold = vault.authority_fold()?;
    Ok(fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash))
}
