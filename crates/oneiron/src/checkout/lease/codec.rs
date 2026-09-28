//! Lease storage codec: vault_meta key builders, txn load/store, and MessagePack codecs.

use std::io::Cursor;

use rmpv::Value;

use super::types::{
    CHECKOUT_LEASE_SCHEMA_VERSION, CHECKOUT_RESULT_ID_DOMAIN, CheckoutError, CheckoutId,
    CheckoutLeaseAct, CheckoutLeaseState, CheckoutResult, CheckoutSettlementDisposition,
    CheckoutSettlementReceipt, CheckoutTaskClass,
};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::side_table::{self, Raw, RawValue, SideKey, SideTable};

/// Checkout lease act. Key: hex32.
pub(crate) const LEASE: SideTable<CheckoutId, CheckoutLeaseAct, Raw> =
    SideTable::new(&side_table::CHECKOUT_LEASE);

/// Retired checkout epoch high-water mark. Key: hex32.
pub(in crate::checkout) const TOMBSTONE: SideTable<CheckoutId, TombstoneRow, Raw> =
    SideTable::new(&side_table::CHECKOUT_TOMBSTONE);

/// Checkout settlement receipt. Key: hex32 + decimal + hex64.
pub(crate) const SETTLEMENT: SideTable<SettlementKey, CheckoutSettlementReceipt, Raw> =
    SideTable::new(&side_table::CHECKOUT_SETTLEMENT);

/// [`SETTLEMENT`]'s key: the checkout id's hex text, a literal `:`, the epoch as decimal text, a
/// literal `:`, then the result identity's hex text — the byte layout the module has always
/// spelled (never decoded back into fields: every reader already holds the exact key it wrote).
pub(in crate::checkout) struct SettlementKey {
    pub(in crate::checkout) checkout_id: CheckoutId,
    pub(in crate::checkout) epoch: u64,
    pub(in crate::checkout) identity: [u8; 32],
}
impl SideKey for SettlementKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.checkout_id.encode_into(out);
        out.push(b':');
        out.extend_from_slice(self.epoch.to_string().as_bytes());
        out.push(b':');
        for byte in self.identity {
            out.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (id_part, rest) = text.split_at_checked(32)?;
        let rest = rest.strip_prefix(':')?;
        let separator = rest.find(':')?;
        let (epoch_part, rest) = rest.split_at(separator);
        let identity_part = rest.strip_prefix(':')?;
        if identity_part.len() != 64 {
            return None;
        }
        let checkout_id = CheckoutId::decode_key(id_part.as_bytes())?;
        let epoch = epoch_part.parse::<u64>().ok()?;
        let mut identity = [0_u8; 32];
        for (index, byte) in identity.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&identity_part[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(Self {
            checkout_id,
            epoch,
            identity,
        })
    }
}

/// [`TOMBSTONE`]'s row: the byte layout [`encode_tombstone`]/[`decode_tombstone`] have always
/// spelled.
pub(in crate::checkout) struct TombstoneRow(pub(in crate::checkout) u64);
impl RawValue for TombstoneRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        encode_tombstone(self.0)
            .map_err(|_| Error::InvariantViolation("checkout lease record").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        decode_tombstone(bytes)
            .map(Self)
            .map_err(|_| Error::CorruptedIndex("checkout lease record").into())
    }
}

impl RawValue for CheckoutLeaseAct {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        encode_act(self).map_err(|_| Error::InvariantViolation("checkout lease record").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        decode_act(bytes).map_err(|_| Error::CorruptedIndex("checkout lease record").into())
    }
}

impl RawValue for CheckoutSettlementReceipt {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        encode_receipt(self).map_err(|_| Error::InvariantViolation("checkout lease record").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        decode_receipt(bytes).map_err(|_| Error::CorruptedIndex("checkout lease record").into())
    }
}

/// Test-only now: every non-test read/write of [`LEASE`] goes through the typed door directly.
#[cfg(test)]
pub(crate) fn lease_key(id: CheckoutId) -> Vec<u8> {
    LEASE.key_bytes(&id)
}
/// Test-only now: every non-test read/write of [`TOMBSTONE`] goes through the typed door
/// directly.
#[cfg(test)]
pub(in crate::checkout) fn tombstone_key(id: CheckoutId) -> Vec<u8> {
    TOMBSTONE.key_bytes(&id)
}
/// Highest epoch ever retired for `id`, or `None` when no lifecycle of `id` has
/// ever been torn down. A decode failure is fail-closed (`corrupt`), never a
/// silent `None`, so a damaged tombstone can never reissue a used epoch.
pub(super) fn load_tombstone_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    id: CheckoutId,
) -> CheckoutResult<Option<u64>> {
    Ok(TOMBSTONE.get(&vault.store, t, &id)?.map(|row| row.0))
}
pub(crate) fn load_act_in_txn(
    vault: &Vault,
    t: &heed::RoTxn<'_>,
    id: CheckoutId,
) -> CheckoutResult<Option<CheckoutLeaseAct>> {
    Ok(LEASE.get(&vault.store, t, &id)?)
}
pub(super) fn store_act_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    a: &CheckoutLeaseAct,
) -> CheckoutResult<()> {
    LEASE.put(&vault.store, t, &a.checkout_id, a)?;
    Ok(())
}
pub fn checkout_result_identity(
    id: CheckoutId,
    epoch: u64,
    observed: &str,
    result: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CHECKOUT_RESULT_ID_DOMAIN);
    h.update(id.as_bytes());
    h.update(&epoch.to_le_bytes());
    h.update(observed.as_bytes());
    h.update(&[0]);
    h.update(result.as_bytes());
    *h.finalize().as_bytes()
}
/// Test-only now: every non-test read/write of [`SETTLEMENT`] goes through the typed door
/// directly.
#[cfg(test)]
pub(crate) fn settlement_key(id: CheckoutId, epoch: u64, identity: [u8; 32]) -> Vec<u8> {
    SETTLEMENT.key_bytes(&SettlementKey {
        checkout_id: id,
        epoch,
        identity,
    })
}
const CHECKOUT_LEASE_BODY_KEYS: [&str; 11] = [
    "schema_version",
    "checkout_id",
    "task_ref",
    "repo_ref",
    "holder_ref",
    "epoch",
    "task_class",
    "state",
    "claimed_at",
    "lease_expires_at",
    "updated_at",
];
const CHECKOUT_SETTLEMENT_BODY_KEYS: [&str; 9] = [
    "schema_version",
    "checkout_id",
    "epoch",
    "result_identity",
    "disposition",
    "observed_ref",
    "result_ref",
    "settled_at",
    "receipt_id",
];
const CHECKOUT_TOMBSTONE_BODY_KEYS: [&str; 2] = ["schema_version", "max_epoch"];
fn corrupt() -> CheckoutError {
    CheckoutError::Store(Error::CorruptedIndex("checkout lease record"))
}
fn map_bytes(entries: Vec<(&str, Value)>) -> CheckoutResult<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::from(k), v))
                .collect(),
        ),
    )
    .map_err(|_| corrupt())?;
    Ok(out)
}
fn fields(bytes: &[u8], keys: &[&str]) -> CheckoutResult<Vec<Value>> {
    let mut c = Cursor::new(bytes);
    let v = rmpv::decode::read_value(&mut c).map_err(|_| corrupt())?;
    if c.position() as usize != bytes.len() {
        return Err(corrupt());
    }
    let Value::Map(xs) = v else {
        return Err(corrupt());
    };
    if xs.len() != keys.len() {
        return Err(corrupt());
    };
    keys.iter()
        .map(|key| {
            xs.iter()
                .find_map(|(k, v)| (k.as_str() == Some(*key)).then(|| v.clone()))
                .ok_or_else(corrupt)
        })
        .collect()
}
fn text(v: &Value) -> CheckoutResult<String> {
    v.as_str().map(str::to_owned).ok_or_else(corrupt)
}
fn u(v: &Value) -> CheckoutResult<u64> {
    v.as_u64().ok_or_else(corrupt)
}
pub(in crate::checkout) fn encode_act(a: &CheckoutLeaseAct) -> CheckoutResult<Vec<u8>> {
    map_bytes(vec![
        (
            CHECKOUT_LEASE_BODY_KEYS[0],
            Value::from(CHECKOUT_LEASE_SCHEMA_VERSION),
        ),
        (
            CHECKOUT_LEASE_BODY_KEYS[1],
            Value::Binary(a.checkout_id.as_bytes().to_vec()),
        ),
        (
            CHECKOUT_LEASE_BODY_KEYS[2],
            Value::Binary(a.task_ref.as_bytes().to_vec()),
        ),
        (
            CHECKOUT_LEASE_BODY_KEYS[3],
            Value::from(a.repo_ref.canonical()),
        ),
        (
            CHECKOUT_LEASE_BODY_KEYS[4],
            Value::from(a.holder_ref.as_str()),
        ),
        (CHECKOUT_LEASE_BODY_KEYS[5], Value::from(a.epoch)),
        (
            CHECKOUT_LEASE_BODY_KEYS[6],
            Value::from(a.task_class.as_str()),
        ),
        (
            CHECKOUT_LEASE_BODY_KEYS[7],
            Value::from(match a.state {
                CheckoutLeaseState::Active => "active",
                CheckoutLeaseState::Settling => "settling",
                CheckoutLeaseState::Settled => "settled",
                CheckoutLeaseState::Retained => "retained",
            }),
        ),
        (CHECKOUT_LEASE_BODY_KEYS[8], Value::from(a.claimed_at)),
        (
            CHECKOUT_LEASE_BODY_KEYS[9],
            a.lease_expires_at.map_or(Value::Nil, Value::from),
        ),
        (CHECKOUT_LEASE_BODY_KEYS[10], Value::from(a.updated_at)),
    ])
}
pub(in crate::checkout) fn decode_act(b: &[u8]) -> CheckoutResult<CheckoutLeaseAct> {
    let x = fields(b, &CHECKOUT_LEASE_BODY_KEYS)?;
    if u(&x[0])? != 1 {
        return Err(corrupt());
    };
    let id = x[1]
        .as_slice()
        .filter(|b| b.len() == 16)
        .ok_or_else(corrupt)?;
    let task = x[2]
        .as_slice()
        .filter(|b| b.len() == 16)
        .ok_or_else(corrupt)?;
    let mut ib = [0; 16];
    ib.copy_from_slice(id);
    let mut tb = [0; 16];
    tb.copy_from_slice(task);
    let class = match text(&x[6])?.as_str() {
        "edit" => CheckoutTaskClass::Edit,
        "build" => CheckoutTaskClass::Build,
        "verify" => CheckoutTaskClass::Verify,
        "effect" => CheckoutTaskClass::Effect,
        _ => return Err(corrupt()),
    };
    let state = match text(&x[7])?.as_str() {
        "active" => CheckoutLeaseState::Active,
        "settling" => CheckoutLeaseState::Settling,
        "settled" => CheckoutLeaseState::Settled,
        "retained" => CheckoutLeaseState::Retained,
        _ => return Err(corrupt()),
    };
    let holder = text(&x[4])?;
    if holder.is_empty() {
        return Err(corrupt());
    };
    Ok(CheckoutLeaseAct {
        checkout_id: CheckoutId::from_bytes(ib)?,
        task_ref: EntityId::from_bytes(tb).map_err(CheckoutError::Store)?,
        repo_ref: RepoRef::parse(&text(&x[3])?).map_err(CheckoutError::Store)?,
        holder_ref: holder,
        epoch: u(&x[5])?,
        task_class: class,
        state,
        claimed_at: u(&x[8])?,
        lease_expires_at: if x[9].is_nil() { None } else { Some(u(&x[9])?) },
        updated_at: u(&x[10])?,
    })
}
pub(in crate::checkout) fn encode_tombstone(max_epoch: u64) -> CheckoutResult<Vec<u8>> {
    map_bytes(vec![
        (CHECKOUT_TOMBSTONE_BODY_KEYS[0], Value::from(1)),
        (CHECKOUT_TOMBSTONE_BODY_KEYS[1], Value::from(max_epoch)),
    ])
}
pub(in crate::checkout) fn decode_tombstone(b: &[u8]) -> CheckoutResult<u64> {
    let x = fields(b, &CHECKOUT_TOMBSTONE_BODY_KEYS)?;
    if u(&x[0])? != 1 {
        return Err(corrupt());
    };
    // Teardown never records epoch 0, so a stored 0 is corruption: accepting it
    // would read as "never torn down" and reissue epoch 1 to a fresh lifecycle.
    let max_epoch = u(&x[1])?;
    if max_epoch == 0 {
        return Err(corrupt());
    }
    Ok(max_epoch)
}
pub(in crate::checkout) fn encode_receipt(
    r: &CheckoutSettlementReceipt,
) -> CheckoutResult<Vec<u8>> {
    map_bytes(vec![
        (CHECKOUT_SETTLEMENT_BODY_KEYS[0], Value::from(1)),
        (
            CHECKOUT_SETTLEMENT_BODY_KEYS[1],
            Value::Binary(r.checkout_id.as_bytes().to_vec()),
        ),
        (CHECKOUT_SETTLEMENT_BODY_KEYS[2], Value::from(r.epoch)),
        (
            CHECKOUT_SETTLEMENT_BODY_KEYS[3],
            Value::Binary(r.result_identity.to_vec()),
        ),
        (
            CHECKOUT_SETTLEMENT_BODY_KEYS[4],
            Value::from(match r.disposition {
                CheckoutSettlementDisposition::Select => "select",
                CheckoutSettlementDisposition::Apply => "apply",
                CheckoutSettlementDisposition::Release => "release",
                CheckoutSettlementDisposition::Discard => "discard",
            }),
        ),
        (
            CHECKOUT_SETTLEMENT_BODY_KEYS[5],
            Value::from(r.observed_ref.as_str()),
        ),
        (
            CHECKOUT_SETTLEMENT_BODY_KEYS[6],
            Value::from(r.result_ref.as_str()),
        ),
        (CHECKOUT_SETTLEMENT_BODY_KEYS[7], Value::from(r.settled_at)),
        (
            CHECKOUT_SETTLEMENT_BODY_KEYS[8],
            Value::Binary(r.receipt_id.to_vec()),
        ),
    ])
}
pub(in crate::checkout) fn decode_receipt(b: &[u8]) -> CheckoutResult<CheckoutSettlementReceipt> {
    let x = fields(b, &CHECKOUT_SETTLEMENT_BODY_KEYS)?;
    if u(&x[0])? != 1 {
        return Err(corrupt());
    };
    let cv = x[1]
        .as_slice()
        .filter(|v| v.len() == 16)
        .ok_or_else(corrupt)?;
    let rv = x[3]
        .as_slice()
        .filter(|v| v.len() == 32)
        .ok_or_else(corrupt)?;
    let iv = x[8]
        .as_slice()
        .filter(|v| v.len() == 32)
        .ok_or_else(corrupt)?;
    let mut c = [0; 16];
    c.copy_from_slice(cv);
    let mut ri = [0; 32];
    ri.copy_from_slice(rv);
    let mut id = [0; 32];
    id.copy_from_slice(iv);
    let disposition = match text(&x[4])?.as_str() {
        "select" => CheckoutSettlementDisposition::Select,
        "apply" => CheckoutSettlementDisposition::Apply,
        "release" => CheckoutSettlementDisposition::Release,
        "discard" => CheckoutSettlementDisposition::Discard,
        _ => return Err(corrupt()),
    };
    Ok(CheckoutSettlementReceipt {
        receipt_id: id,
        checkout_id: CheckoutId::from_bytes(c)?,
        epoch: u(&x[2])?,
        result_identity: ri,
        disposition,
        observed_ref: text(&x[5])?,
        result_ref: text(&x[6])?,
        settled_at: u(&x[7])?,
    })
}
