use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::Error;
use std::fmt;

pub const CHECKOUT_LEASE_SCHEMA_VERSION: u8 = 1;
pub const CHECKOUT_LEASE_KEY_PREFIX: &[u8] = b"checkout:lease:v1:";
pub const CHECKOUT_SETTLEMENT_KEY_PREFIX: &[u8] = b"checkout:settlement:v1:";
pub const CHECKOUT_RESULT_ID_DOMAIN: &[u8] = b"oneiron:checkout-result:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckoutId(pub [u8; 16]);
impl CheckoutId {
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
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
        if self.read(r.checkout_id)?.is_some() {
            return Err(CheckoutError::StaleEpoch {
                held: 1,
                presented: 0,
            });
        };
        let a = CheckoutLeaseAct {
            checkout_id: r.checkout_id,
            task_ref: r.task_ref,
            repo_ref: r.repo_ref,
            holder_ref: r.holder_ref.clone(),
            epoch: 1,
            task_class: r.task_class,
            state: CheckoutLeaseState::Active,
            claimed_at: r.now,
            lease_expires_at: r.ttl_secs.map(|x| r.now.saturating_add(x)),
            updated_at: r.now,
        };
        self.write(&a)?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Claimed {
                task_ref: a.task_ref,
                assignee_ref: a.holder_ref.clone(),
                started_at: r.now,
                epoch: 1,
            })?;
        self.liveness.publish(CheckoutLivenessPulse {
            checkout_id: a.checkout_id,
            epoch: 1,
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
        let mut a = self.fenced(&f)?;
        a.lease_expires_at = Some(now.saturating_add(ttl));
        a.updated_at = now;
        self.write(&a)?;
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
        let mut a = self
            .read(id)?
            .ok_or(CheckoutError::Invalid("checkout missing"))?;
        if a.holder_ref == new {
            return Ok(grant(&a));
        }
        if !a.task_class.allows_ttl_reclaim() || a.lease_expires_at.is_none_or(|x| now < x) {
            return Err(CheckoutError::StaleEpoch {
                held: a.epoch,
                presented: a.epoch,
            });
        }
        a.epoch += 1;
        a.holder_ref = new;
        a.updated_at = now;
        a.lease_expires_at = a
            .lease_expires_at
            .map(|x| now.saturating_add(x.saturating_sub(a.claimed_at)));
        self.write(&a)?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Reclaimed {
                task_ref: a.task_ref,
                assignee_ref: a.holder_ref.clone(),
                epoch: a.epoch,
            })?;
        self.liveness.publish(CheckoutLivenessPulse {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
            holder_ref: a.holder_ref.clone(),
            observed_at: now,
        })?;
        Ok(grant(&a))
    }
    pub fn settle(
        &mut self,
        r: CheckoutSettlementRequest,
    ) -> CheckoutResult<CheckoutSettlementReceipt> {
        let mut a = self.fenced(&r.fence)?;
        let identity =
            checkout_result_identity(a.checkout_id, a.epoch, &r.observed_ref, &r.result_ref);
        let key = settlement_key(identity);
        if self.get_raw(&key)?.is_some() {
            return Err(CheckoutError::SettlementAlreadyWon);
        }
        let receipt = CheckoutSettlementReceipt {
            receipt_id: *blake3::hash(&[identity.as_slice(), &r.now.to_le_bytes()].concat())
                .as_bytes(),
            checkout_id: a.checkout_id,
            epoch: a.epoch,
            result_identity: identity,
            disposition: r.disposition,
            result_ref: r.result_ref.clone(),
            settled_at: r.now,
        };
        self.put_raw(&key, &encode_receipt(&receipt))?;
        a.state = CheckoutLeaseState::Settled;
        a.updated_at = r.now;
        self.write(&a)?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Settled {
                task_ref: a.task_ref,
                epoch: a.epoch,
                result_ref: r.result_ref,
            })?;
        Ok(receipt)
    }
    pub fn teardown<R: CheckoutRepoOps>(
        &mut self,
        f: CheckoutLeaseFence,
        receipt: Option<&PushedHeadReceipt>,
        ops: &R,
        _now: u64,
    ) -> CheckoutResult<CheckoutTeardownOutcome> {
        let a = self.fenced(&f)?;
        let Some(r) = receipt else {
            return Ok(retained(&a, CheckoutRetainReason::MissingPushedHeadReceipt));
        };
        if r.checkout_id != a.checkout_id || r.epoch != a.epoch {
            return Ok(retained(&a, CheckoutRetainReason::ReceiptMismatch));
        };
        let i = ops.inspect_teardown(&a, r)?;
        if i.occupant.is_some() || self.liveness.current(a.checkout_id)?.is_some() {
            return Ok(retained(&a, CheckoutRetainReason::LiveOccupant));
        }
        if i.dirty || i.receipt_match == TeardownReceiptMatch::Uncertain {
            return Ok(retained(&a, CheckoutRetainReason::DirtyOrUncertain));
        }
        if i.receipt_match != TeardownReceiptMatch::Match
            || i.observed_head
                .as_ref()
                .is_none_or(|h| h.to_string() != r.pushed_head)
        {
            return Ok(retained(&a, CheckoutRetainReason::ReceiptMismatch));
        }
        ops.collect(&a)?;
        self.delete(a.checkout_id)?;
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
    fn fenced(&self, f: &CheckoutLeaseFence) -> CheckoutResult<CheckoutLeaseAct> {
        let a = self
            .read(f.checkout_id)?
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
    fn key(id: CheckoutId) -> Vec<u8> {
        [CHECKOUT_LEASE_KEY_PREFIX, id.to_hex().as_bytes()].concat()
    }
    fn read(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLeaseAct>> {
        self.get_raw(&Self::key(id))?
            .map(|b| decode_act(&b))
            .transpose()
    }
    fn write(&self, a: &CheckoutLeaseAct) -> CheckoutResult<()> {
        self.put_raw(&Self::key(a.checkout_id), &encode_act(a))
    }
    fn delete(&self, id: CheckoutId) -> CheckoutResult<()> {
        let key = Self::key(id);
        self.vault
            .with_write_txn(|t| {
                self.vault.store.vault_meta.delete(t, &key)?;
                Ok(())
            })
            .map_err(Into::into)
    }
    fn get_raw(&self, key: &[u8]) -> CheckoutResult<Option<Vec<u8>>> {
        let t = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(self
            .vault
            .store
            .vault_meta
            .get(&t, key)?
            .map(|x| x.to_vec()))
    }
    fn put_raw(&self, key: &[u8], v: &[u8]) -> CheckoutResult<()> {
        self.vault
            .with_write_txn(|t| {
                self.vault.store.vault_meta.put(t, key, v)?;
                Ok(())
            })
            .map_err(Into::into)
    }
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
    h.update(&id.0);
    h.update(&epoch.to_le_bytes());
    h.update(observed.as_bytes());
    h.update(&[0]);
    h.update(result.as_bytes());
    *h.finalize().as_bytes()
}
fn settlement_key(id: [u8; 32]) -> Vec<u8> {
    [CHECKOUT_SETTLEMENT_KEY_PREFIX, id.as_slice()].concat()
}
// Fixed-width durable encoding deliberately excludes liveness pulses.
fn encode_act(a: &CheckoutLeaseAct) -> Vec<u8> {
    format!(
        "1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        a.checkout_id.to_hex(),
        a.task_ref.to_hex(),
        a.repo_ref.canonical(),
        a.holder_ref,
        a.epoch,
        a.task_class.as_str(),
        match a.state {
            CheckoutLeaseState::Active => "active",
            CheckoutLeaseState::Settling => "settling",
            CheckoutLeaseState::Settled => "settled",
            CheckoutLeaseState::Retained => "retained",
        },
        a.claimed_at,
        a.lease_expires_at.map_or("".into(), |x| x.to_string()),
        a.updated_at
    )
    .into_bytes()
}
fn decode_act(b: &[u8]) -> CheckoutResult<CheckoutLeaseAct> {
    let s = std::str::from_utf8(b)
        .map_err(|_| CheckoutError::Store(Error::CorruptedIndex("checkout lease record")))?;
    let x: Vec<_> = s.split('|').collect();
    if x.len() != 11 || x[0] != "1" {
        return Err(CheckoutError::Store(Error::CorruptedIndex(
            "checkout lease record",
        )));
    }
    let mut raw = [0; 16];
    if x[1].len() != 32 {
        return Err(CheckoutError::Store(Error::CorruptedIndex(
            "checkout lease record",
        )));
    }
    for (i, p) in x[1].as_bytes().chunks(2).enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(p).unwrap_or(""), 16)
            .map_err(|_| CheckoutError::Store(Error::CorruptedIndex("checkout lease record")))?;
    }
    let task = EntityId::from_hex(x[2]).map_err(CheckoutError::Store)?;
    let repo = RepoRef::parse(x[3]).map_err(CheckoutError::Store)?;
    let class = match x[6] {
        "edit" => CheckoutTaskClass::Edit,
        "build" => CheckoutTaskClass::Build,
        "verify" => CheckoutTaskClass::Verify,
        "effect" => CheckoutTaskClass::Effect,
        _ => {
            return Err(CheckoutError::Store(Error::CorruptedIndex(
                "checkout lease record",
            )));
        }
    };
    let state = match x[7] {
        "active" => CheckoutLeaseState::Active,
        "settling" => CheckoutLeaseState::Settling,
        "settled" => CheckoutLeaseState::Settled,
        "retained" => CheckoutLeaseState::Retained,
        _ => {
            return Err(CheckoutError::Store(Error::CorruptedIndex(
                "checkout lease record",
            )));
        }
    };
    Ok(CheckoutLeaseAct {
        checkout_id: CheckoutId(raw),
        task_ref: task,
        repo_ref: repo,
        holder_ref: x[4].into(),
        epoch: x[5]
            .parse()
            .map_err(|_| CheckoutError::Store(Error::CorruptedIndex("checkout lease record")))?,
        task_class: class,
        state,
        claimed_at: x[8]
            .parse()
            .map_err(|_| CheckoutError::Store(Error::CorruptedIndex("checkout lease record")))?,
        lease_expires_at: if x[9].is_empty() {
            None
        } else {
            Some(x[9].parse().map_err(|_| {
                CheckoutError::Store(Error::CorruptedIndex("checkout lease record"))
            })?)
        },
        updated_at: x[10]
            .parse()
            .map_err(|_| CheckoutError::Store(Error::CorruptedIndex("checkout lease record")))?,
    })
}
fn encode_receipt(r: &CheckoutSettlementReceipt) -> Vec<u8> {
    format!(
        "1|{}|{}|{}|{}|{}|{}",
        r.checkout_id.to_hex(),
        r.epoch,
        r.result_identity
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        r.disposition as u8,
        r.result_ref,
        r.settled_at
    )
    .into_bytes()
}
