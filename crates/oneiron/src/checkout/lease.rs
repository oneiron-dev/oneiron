use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::Error;
use rmpv::Value;
use std::fmt;
use std::io::Cursor;

pub const CHECKOUT_LEASE_SCHEMA_VERSION: u8 = 1;
pub const CHECKOUT_LEASE_KEY_PREFIX: &[u8] = b"checkout:lease:v1:";
pub const CHECKOUT_SETTLEMENT_KEY_PREFIX: &[u8] = b"checkout:settlement:v1:";
pub const CHECKOUT_RESULT_ID_DOMAIN: &[u8] = b"oneiron:checkout-result:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckoutId([u8; 16]);
impl CheckoutId {
    pub fn from_bytes(bytes: [u8; 16]) -> CheckoutResult<Self> {
        if bytes == [0; 16] {
            return Err(CheckoutError::Invalid("checkout id zero"));
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl fmt::Display for CheckoutId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitOid([u8; 20]);
impl GitOid {
    pub fn parse(value: &str) -> CheckoutResult<Self> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(CheckoutError::Invalid(
                "git oid must be 40 lower-hex characters",
            ));
        }
        let mut bytes = [0; 20];
        for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| CheckoutError::Invalid("git oid"))?,
                16,
            )
            .map_err(|_| CheckoutError::Invalid("git oid"))?;
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}
impl fmt::Display for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutTaskClass {
    Edit,
    Build,
    Verify,
    Effect,
}
impl CheckoutTaskClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Build => "build",
            Self::Verify => "verify",
            Self::Effect => "effect",
        }
    }
    pub const fn allows_ttl_reclaim(self) -> bool {
        matches!(self, Self::Build | Self::Verify)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutLeaseState {
    Active,
    Settling,
    Settled,
    Retained,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLeaseAct {
    pub checkout_id: CheckoutId,
    pub task_ref: EntityId,
    pub repo_ref: RepoRef,
    pub holder_ref: String,
    pub epoch: u64,
    pub task_class: CheckoutTaskClass,
    pub state: CheckoutLeaseState,
    pub claimed_at: u64,
    pub lease_expires_at: Option<u64>,
    pub updated_at: u64,
}
pub type CheckoutHolder = String;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckoutFactMutation {
    Claimed {
        task_ref: EntityId,
        assignee_ref: String,
        started_at: u64,
        epoch: u64,
    },
    Reclaimed {
        task_ref: EntityId,
        assignee_ref: String,
        epoch: u64,
    },
    Settled {
        task_ref: EntityId,
        epoch: u64,
        result_ref: String,
    },
    Released {
        task_ref: EntityId,
        epoch: u64,
    },
}
pub trait CheckoutFactSink {
    fn apply_checkout_fact(&mut self, mutation: CheckoutFactMutation) -> CheckoutResult<()>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLivenessPulse {
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub holder_ref: String,
    pub observed_at: u64,
}
pub trait CheckoutLiveness {
    fn publish(&mut self, pulse: CheckoutLivenessPulse) -> CheckoutResult<()>;
    fn current(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>>;
    fn clear(&mut self, id: CheckoutId, epoch: u64) -> CheckoutResult<()>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutClaimRequest {
    pub checkout_id: CheckoutId,
    pub task_ref: EntityId,
    pub repo_ref: RepoRef,
    pub holder_ref: String,
    pub task_class: CheckoutTaskClass,
    pub ttl_secs: Option<u64>,
    pub now: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLeaseGrant {
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub holder_ref: String,
    pub lease_expires_at: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLeaseFence {
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub holder_ref: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutSettlementDisposition {
    Select,
    Apply,
    Release,
    Discard,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSettlementRequest {
    pub fence: CheckoutLeaseFence,
    pub disposition: CheckoutSettlementDisposition,
    pub observed_ref: String,
    pub result_ref: String,
    pub now: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSettlementReceipt {
    pub receipt_id: [u8; 32],
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub result_identity: [u8; 32],
    pub disposition: CheckoutSettlementDisposition,
    pub observed_ref: String,
    pub result_ref: String,
    pub settled_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedHeadReceipt {
    pub receipt_ref: String,
    pub observed_ref: String,
    pub pushed_head: String,
    pub checkout_id: CheckoutId,
    pub epoch: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckoutTeardownOutcome {
    Collected {
        checkout_id: CheckoutId,
        epoch: u64,
    },
    Retained {
        checkout_id: CheckoutId,
        epoch: u64,
        reason: CheckoutRetainReason,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutRetainReason {
    MissingPushedHeadReceipt,
    ReceiptMismatch,
    LiveOccupant,
    DirtyOrUncertain,
}
#[derive(Debug)]
pub enum CheckoutError {
    StaleEpoch { held: u64, presented: u64 },
    LivenessOccupied { occupant: CheckoutHolder },
    ReceiptMismatch,
    SettlementAlreadyWon,
    RepoOps(String),
    Store(Error),
    Invalid(&'static str),
}
impl From<Error> for CheckoutError {
    fn from(e: Error) -> Self {
        Self::Store(e)
    }
}
pub type CheckoutResult<T> = Result<T, CheckoutError>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutTeardownInspection {
    pub observed_head: Option<GitOid>,
    pub dirty: bool,
    pub receipt_match: TeardownReceiptMatch,
    pub occupant: Option<CheckoutHolder>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReceiptMatch {
    Match,
    Mismatch,
    Uncertain,
}
pub trait CheckoutRepoOps {
    fn materialize(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()>;
    fn inspect_teardown(
        &self,
        lease: &CheckoutLeaseAct,
        receipt: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection>;
    fn collect(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()>;
}

pub struct CheckoutLeaseService<'a, F, L> {
    vault: &'a Vault,
    facts: F,
    liveness: L,
}
impl<'a, F, L> CheckoutLeaseService<'a, F, L> {
    pub fn new(vault: &'a Vault, facts: F, liveness: L) -> Self {
        Self {
            vault,
            facts,
            liveness,
        }
    }
    pub fn into_parts(self) -> (F, L) {
        (self.facts, self.liveness)
    }
}
impl<F: CheckoutFactSink, L: CheckoutLiveness> CheckoutLeaseService<'_, F, L> {
    pub fn claim(&mut self, r: CheckoutClaimRequest) -> CheckoutResult<CheckoutLeaseGrant> {
        CheckoutId::from_bytes(*r.checkout_id.as_bytes())?;
        if r.holder_ref.is_empty() {
            return Err(CheckoutError::Invalid("checkout holder empty"));
        }
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            if load_act_in_txn(self.vault, t, r.checkout_id)?.is_some() {
                return Err(CheckoutError::StaleEpoch {
                    held: 1,
                    presented: 0,
                });
            }
            let expires = r
                .ttl_secs
                .map(|ttl| {
                    r.now
                        .checked_add(ttl)
                        .ok_or(CheckoutError::Invalid("lease expiry overflow"))
                })
                .transpose()?;
            let a = CheckoutLeaseAct {
                checkout_id: r.checkout_id,
                task_ref: r.task_ref,
                repo_ref: r.repo_ref.clone(),
                holder_ref: r.holder_ref.clone(),
                epoch: 1,
                task_class: r.task_class,
                state: CheckoutLeaseState::Active,
                claimed_at: r.now,
                lease_expires_at: expires,
                updated_at: r.now,
            };
            store_act_in_txn(self.vault, t, &a)?;
            Ok(a)
        })?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Claimed {
                task_ref: a.task_ref,
                assignee_ref: a.holder_ref.clone(),
                started_at: r.now,
                epoch: a.epoch,
            })?;
        self.liveness.publish(CheckoutLivenessPulse {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
            holder_ref: a.holder_ref.clone(),
            observed_at: r.now,
        })?;
        Ok(grant(&a))
    }
    pub fn renew(
        &mut self,
        f: CheckoutLeaseFence,
        ttl: u64,
        now: u64,
    ) -> CheckoutResult<CheckoutLeaseGrant> {
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut a = fenced_in_txn(self.vault, t, &f)?;
            require_not_regressed(&a, now)?;
            require_active(&a)?;
            a.lease_expires_at = Some(
                now.checked_add(ttl)
                    .ok_or(CheckoutError::Invalid("lease expiry overflow"))?,
            );
            a.updated_at = now;
            store_act_in_txn(self.vault, t, &a)?;
            Ok(a)
        })?;
        self.liveness.publish(CheckoutLivenessPulse {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
            holder_ref: a.holder_ref.clone(),
            observed_at: now,
        })?;
        Ok(grant(&a))
    }
    pub fn reclaim_idempotent(
        &mut self,
        id: CheckoutId,
        new: String,
        now: u64,
    ) -> CheckoutResult<CheckoutLeaseGrant> {
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut a = load_act_in_txn(self.vault, t, id)?
                .ok_or(CheckoutError::Invalid("checkout missing"))?;
            require_not_regressed(&a, now)?;
            require_active(&a)?;
            if a.holder_ref == new {
                return Ok((a, false));
            }
            let expiry = a
                .lease_expires_at
                .ok_or(CheckoutError::Invalid("ttl reclaim requires ttl"))?;
            if !a.task_class.allows_ttl_reclaim() || now < expiry {
                return Err(CheckoutError::StaleEpoch {
                    held: a.epoch,
                    presented: a.epoch,
                });
            }
            let ttl = expiry
                .checked_sub(a.updated_at)
                .ok_or(CheckoutError::Invalid("invalid lease ttl"))?;
            a.epoch = a
                .epoch
                .checked_add(1)
                .ok_or(CheckoutError::Invalid("lease epoch overflow"))?;
            a.holder_ref = new.clone();
            a.updated_at = now;
            a.lease_expires_at = Some(
                now.checked_add(ttl)
                    .ok_or(CheckoutError::Invalid("lease expiry overflow"))?,
            );
            store_act_in_txn(self.vault, t, &a)?;
            Ok((a, true))
        })?;
        if a.1 {
            self.facts
                .apply_checkout_fact(CheckoutFactMutation::Reclaimed {
                    task_ref: a.0.task_ref,
                    assignee_ref: a.0.holder_ref.clone(),
                    epoch: a.0.epoch,
                })?;
            self.liveness.publish(CheckoutLivenessPulse {
                checkout_id: a.0.checkout_id,
                epoch: a.0.epoch,
                holder_ref: a.0.holder_ref.clone(),
                observed_at: now,
            })?;
        }
        Ok(grant(&a.0))
    }
    pub fn get(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLeaseAct>> {
        let t = self.vault.store.env.read_txn().map_err(Error::from)?;
        match self.vault.store.vault_meta.get(&t, &lease_key(id))? {
            Some(raw) => Ok(Some(decode_act(&raw)?)),
            None => Ok(None),
        }
    }
    pub fn settle(
        &mut self,
        r: CheckoutSettlementRequest,
    ) -> CheckoutResult<CheckoutSettlementReceipt> {
        if r.observed_ref.is_empty() || r.result_ref.is_empty() {
            return Err(CheckoutError::Invalid("settlement references empty"));
        }
        let (a, receipt, new) = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut a = fenced_in_txn(self.vault, t, &r.fence)?;
            require_not_regressed(&a, r.now)?;
            let identity =
                checkout_result_identity(a.checkout_id, a.epoch, &r.observed_ref, &r.result_ref);
            let prefix = settlement_prefix(a.checkout_id, a.epoch);
            if let Some(row) = self
                .vault
                .store
                .vault_meta
                .prefix_iter(&*t, &prefix)?
                .next()
            {
                let (_, raw) = row?;
                let old = decode_receipt(&raw)?;
                if old.checkout_id == a.checkout_id
                    && old.epoch == a.epoch
                    && old.result_identity == identity
                    && old.disposition == r.disposition
                    && old.observed_ref == r.observed_ref
                    && old.result_ref == r.result_ref
                {
                    return Ok((a, old, false));
                }
                return Err(CheckoutError::SettlementAlreadyWon);
            }
            require_settleable(&a)?;
            let receipt = CheckoutSettlementReceipt {
                receipt_id: *blake3::hash(&[identity.as_slice(), &r.now.to_le_bytes()].concat())
                    .as_bytes(),
                checkout_id: a.checkout_id,
                epoch: a.epoch,
                result_identity: identity,
                disposition: r.disposition,
                observed_ref: r.observed_ref.clone(),
                result_ref: r.result_ref.clone(),
                settled_at: r.now,
            };
            self.vault.store.vault_meta.put(
                t,
                &settlement_key(a.checkout_id, a.epoch, identity),
                &encode_receipt(&receipt)?,
            )?;
            a.state = CheckoutLeaseState::Settled;
            a.updated_at = r.now;
            store_act_in_txn(self.vault, t, &a)?;
            Ok((a, receipt, true))
        })?;
        if new {
            let fact = if receipt.disposition == CheckoutSettlementDisposition::Release {
                CheckoutFactMutation::Released {
                    task_ref: a.task_ref,
                    epoch: a.epoch,
                }
            } else {
                CheckoutFactMutation::Settled {
                    task_ref: a.task_ref,
                    epoch: a.epoch,
                    result_ref: r.result_ref,
                }
            };
            self.facts.apply_checkout_fact(fact)?;
        }
        Ok(receipt)
    }
    pub fn teardown<R: CheckoutRepoOps>(
        &mut self,
        f: CheckoutLeaseFence,
        receipt: Option<&PushedHeadReceipt>,
        ops: &R,
        now: u64,
    ) -> CheckoutResult<CheckoutTeardownOutcome> {
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut current = fenced_in_txn(self.vault, t, &f)?;
            require_not_regressed(&current, now)?;
            require_active(&current)?;
            current.state = CheckoutLeaseState::Settling;
            current.updated_at = now;
            store_act_in_txn(self.vault, t, &current)?;
            Ok(current)
        })?;
        let inspection = match receipt {
            None => Ok(None),
            Some(r) if r.checkout_id != a.checkout_id || r.epoch != a.epoch => Ok(None),
            Some(r) => ops.inspect_teardown(&a, r).map(Some),
        };
        let reason = match (receipt, inspection) {
            (_, Err(error)) => {
                self.retain_settling(&f, now)?;
                return Err(error);
            }
            (None, _) => Some(CheckoutRetainReason::MissingPushedHeadReceipt),
            (Some(r), Ok(None)) if r.checkout_id != a.checkout_id || r.epoch != a.epoch => {
                Some(CheckoutRetainReason::ReceiptMismatch)
            }
            (Some(r), Ok(Some(i))) => {
                if i.occupant.is_some() || self.liveness.current(a.checkout_id)?.is_some() {
                    Some(CheckoutRetainReason::LiveOccupant)
                } else if i.dirty || i.receipt_match == TeardownReceiptMatch::Uncertain {
                    Some(CheckoutRetainReason::DirtyOrUncertain)
                } else if i.receipt_match != TeardownReceiptMatch::Match
                    || i.observed_head
                        .as_ref()
                        .is_none_or(|h| h.to_string() != r.pushed_head)
                {
                    Some(CheckoutRetainReason::ReceiptMismatch)
                } else {
                    None
                }
            }
            _ => Some(CheckoutRetainReason::ReceiptMismatch),
        };
        if let Some(reason) = reason {
            self.retain_settling(&f, now)?;
            return Ok(retained(&a, reason));
        }
        if let Err(error) = ops.collect(&a) {
            self.retain_settling(&f, now)?;
            return Err(error);
        }
        self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let current = fenced_in_txn(self.vault, t, &f)?;
            require_settling(&current)?;
            self.vault
                .store
                .vault_meta
                .delete(t, &lease_key(current.checkout_id))?;
            Ok(())
        })?;
        self.liveness.clear(a.checkout_id, a.epoch)?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Released {
                task_ref: a.task_ref,
                epoch: a.epoch,
            })?;
        Ok(CheckoutTeardownOutcome::Collected {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
        })
    }
    fn retain_settling(&self, f: &CheckoutLeaseFence, now: u64) -> CheckoutResult<()> {
        self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut current = fenced_in_txn(self.vault, t, f)?;
            require_settling(&current)?;
            current.state = CheckoutLeaseState::Retained;
            current.updated_at = now;
            store_act_in_txn(self.vault, t, &current)
        })
    }
}
fn require_not_regressed(a: &CheckoutLeaseAct, now: u64) -> CheckoutResult<()> {
    if now < a.updated_at {
        Err(CheckoutError::Invalid("checkout time regressed"))
    } else {
        Ok(())
    }
}
fn require_settleable(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if matches!(
        a.state,
        CheckoutLeaseState::Active | CheckoutLeaseState::Settled
    ) {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
fn require_settling(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if a.state == CheckoutLeaseState::Settling {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
fn require_active(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if a.state == CheckoutLeaseState::Active {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
fn fenced_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    f: &CheckoutLeaseFence,
) -> CheckoutResult<CheckoutLeaseAct> {
    let a = load_act_in_txn(vault, t, f.checkout_id)?
        .ok_or(CheckoutError::Invalid("checkout missing"))?;
    if a.epoch != f.epoch || a.holder_ref != f.holder_ref {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: f.epoch,
        })
    } else {
        Ok(a)
    }
}
pub(crate) fn lease_key(id: CheckoutId) -> Vec<u8> {
    format!(
        "{}{}",
        std::str::from_utf8(CHECKOUT_LEASE_KEY_PREFIX).expect("ASCII"),
        id
    )
    .into_bytes()
}
fn load_act_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    id: CheckoutId,
) -> CheckoutResult<Option<CheckoutLeaseAct>> {
    match vault.store.vault_meta.get(t, &lease_key(id))? {
        Some(b) => Ok(Some(decode_act(&b)?)),
        None => Ok(None),
    }
}
fn store_act_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    a: &CheckoutLeaseAct,
) -> CheckoutResult<()> {
    vault
        .store
        .vault_meta
        .put(t, &lease_key(a.checkout_id), &encode_act(a)?)?;
    Ok(())
}
fn grant(a: &CheckoutLeaseAct) -> CheckoutLeaseGrant {
    CheckoutLeaseGrant {
        checkout_id: a.checkout_id,
        epoch: a.epoch,
        holder_ref: a.holder_ref.clone(),
        lease_expires_at: a.lease_expires_at,
    }
}
fn retained(a: &CheckoutLeaseAct, reason: CheckoutRetainReason) -> CheckoutTeardownOutcome {
    CheckoutTeardownOutcome::Retained {
        checkout_id: a.checkout_id,
        epoch: a.epoch,
        reason,
    }
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
fn settlement_prefix(id: CheckoutId, epoch: u64) -> Vec<u8> {
    format!(
        "{}{}:{epoch}:",
        std::str::from_utf8(CHECKOUT_SETTLEMENT_KEY_PREFIX).expect("ASCII"),
        id
    )
    .into_bytes()
}
fn settlement_key(id: CheckoutId, epoch: u64, identity: [u8; 32]) -> Vec<u8> {
    format!(
        "{}{}",
        String::from_utf8(settlement_prefix(id, epoch)).expect("ASCII"),
        identity
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
    .into_bytes()
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
pub(crate) fn encode_act(a: &CheckoutLeaseAct) -> CheckoutResult<Vec<u8>> {
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
pub(crate) fn decode_act(b: &[u8]) -> CheckoutResult<CheckoutLeaseAct> {
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
pub(crate) fn encode_receipt(r: &CheckoutSettlementReceipt) -> CheckoutResult<Vec<u8>> {
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
pub(crate) fn decode_receipt(b: &[u8]) -> CheckoutResult<CheckoutSettlementReceipt> {
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
