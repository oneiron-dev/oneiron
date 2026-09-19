//! Per-vault signed oversight over healer proposals and review decisions.

use crate::{Error, Result, Vault};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

const ACTIVITY: &[u8] = b"healer:activity:v1:";
const RECEIPT: &[u8] = b"healer:oversight:v1:";
const DOMAIN: &[u8] = b"oneiron:healer-oversight:v1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Activity {
    proposed_at: u64,
    reviewed_at: Option<u64>,
    escalated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversightKind {
    Coverage,
    ReviewLatency,
    EscalationRate,
}
impl OversightKind {
    fn tag(self) -> u8 {
        match self {
            Self::Coverage => 0,
            Self::ReviewLatency => 1,
            Self::EscalationRate => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightCounts {
    pub vault_device: u64,
    pub observed_at: u64,
    pub kind: OversightKind,
    pub proposed: u64,
    pub reviewed: u64,
    pub escalated: u64,
    pub review_latency_secs: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightReceipt {
    pub counts: OversightCounts,
    pub signer: [u8; 32],
    pub signature: Vec<u8>,
}
impl OversightReceipt {
    pub fn verify(&self, expected_signer: &[u8; 32]) -> bool {
        if &self.signer != expected_signer {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(expected_signer) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let Ok(bytes) = signed_bytes(&self.counts) else {
            return false;
        };
        key.verify_strict(&bytes, &signature).is_ok()
    }
}
fn signed_bytes(counts: &OversightCounts) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(
        rmp_serde::to_vec_named(counts).map_err(|_| Error::CorruptedIndex("healer oversight"))?,
    );
    Ok(bytes)
}
fn activity_key(case: &str) -> Result<Vec<u8>> {
    if case.len() != 32
        || !case
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidConfig("invalid healer case ref".into()));
    }
    Ok([ACTIVITY, case.as_bytes()].concat())
}
pub(crate) fn proposed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &str,
    now: u64,
) -> Result<()> {
    let key = activity_key(case)?;
    if vault.store.vault_meta.get(txn, &key)?.is_none() {
        let bytes = rmp_serde::to_vec_named(&Activity {
            proposed_at: now,
            reviewed_at: None,
            escalated: false,
        })
        .map_err(|_| Error::CorruptedIndex("healer activity"))?;
        vault.store.vault_meta.put(txn, &key, &bytes)?;
    }
    Ok(())
}
impl Vault {
    /// The host's reviewed-decision door; this records a fact, never applies a
    /// repair. The ordinary consent gate remains the only repair authority.
    pub fn record_healer_review(&self, case: &str, now: u64, escalated: bool) -> Result<()> {
        let key = activity_key(case)?;
        self.with_write_txn(|txn| {
            let bytes = self
                .store
                .vault_meta
                .get(txn, &key)?
                .ok_or(Error::InvalidConfig("unknown healer case".into()))?;
            let mut activity: Activity = rmp_serde::from_slice(&bytes)
                .map_err(|_| Error::CorruptedIndex("healer activity"))?;
            if now < activity.proposed_at {
                return Err(Error::InvalidConfig("review predates proposal".into()));
            }
            if let Some(prior) = activity.reviewed_at {
                if prior == now && activity.escalated == escalated {
                    return Ok(());
                }
                return Err(Error::InvalidConfig(
                    "healer review already recorded".into(),
                ));
            }
            activity.reviewed_at = Some(now);
            activity.escalated = escalated;
            let bytes = rmp_serde::to_vec_named(&activity)
                .map_err(|_| Error::CorruptedIndex("healer activity"))?;
            self.store.vault_meta.put(txn, &key, &bytes)?;
            Ok(())
        })
    }
    /// Emits all three receipts in one transaction. Each contains counts so
    /// empty denominators remain explicit instead of yielding NaN rates.
    pub fn emit_healer_oversight(&self, now: u64) -> Result<Vec<OversightReceipt>> {
        self.with_write_txn(|txn| {
            let identity = crate::identity::ensure_device_identity_in_txn(self, txn)?;
            let mut counts = OversightCounts {
                vault_device: identity.client_id,
                observed_at: now,
                kind: OversightKind::Coverage,
                proposed: 0,
                reviewed: 0,
                escalated: 0,
                review_latency_secs: 0,
            };
            for row in self.store.vault_meta.prefix_iter(txn, ACTIVITY)? {
                let (_, bytes) = row?;
                let activity: Activity = rmp_serde::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("healer activity"))?;
                if activity.proposed_at > now {
                    continue;
                }
                counts.proposed = counts.proposed.saturating_add(1);
                if let Some(at) = activity.reviewed_at.filter(|at| *at <= now) {
                    counts.reviewed = counts.reviewed.saturating_add(1);
                    counts.review_latency_secs = counts
                        .review_latency_secs
                        .saturating_add(at - activity.proposed_at);
                    counts.escalated = counts
                        .escalated
                        .saturating_add(u64::from(activity.escalated));
                }
            }
            let mut receipts = Vec::new();
            for kind in [
                OversightKind::Coverage,
                OversightKind::ReviewLatency,
                OversightKind::EscalationRate,
            ] {
                let counts = OversightCounts {
                    kind,
                    ..counts.clone()
                };
                let receipt = OversightReceipt {
                    signature: identity
                        .signing_key
                        .sign(&signed_bytes(&counts)?)
                        .to_bytes()
                        .to_vec(),
                    signer: identity.signing_key.verifying_key().to_bytes(),
                    counts,
                };
                let bytes = rmp_serde::to_vec_named(&receipt)
                    .map_err(|_| Error::CorruptedIndex("healer oversight"))?;
                self.store
                    .vault_meta
                    .put(txn, &[RECEIPT, &[kind.tag()]].concat(), &bytes)?;
                receipts.push(receipt);
            }
            Ok(receipts)
        })
    }
}
