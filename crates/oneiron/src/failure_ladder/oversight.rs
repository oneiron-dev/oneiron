//! Per-vault signed oversight over healer proposals and review decisions.

use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"oneiron:healer-oversight:v1\0";

/// Proposed/reviewed/escalated timestamps for one healer case. Key: hex32 (case_ref).
const ACTIVITY: SideTable<String, Activity, Named> = SideTable::new(&side_table::HEALER_ACTIVITY);

/// Latest signed per-vault-device oversight receipt. Key: u8 (OversightKind tag: 0/1/2).
const RECEIPT: SideTable<[u8; 1], OversightReceipt, Named> =
    SideTable::new(&side_table::HEALER_OVERSIGHT_RECEIPT);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Activity {
    proposed_at: u64,
    reviewed_at: Option<u64>,
    escalated: bool,
}

impl Activity {
    /// The business rule `Named`'s plain decode cannot enforce: a review cannot predate its
    /// own proposal. Runs immediately after every decode, direct or through [`ACTIVITY`].
    fn validate_order(&self) -> Result<()> {
        if self.reviewed_at.is_some_and(|at| at < self.proposed_at) {
            return Err(Error::CorruptedIndex("healer activity"));
        }
        Ok(())
    }

    /// Test-only now: every non-test read of [`ACTIVITY`] decodes through the typed door
    /// directly, then calls [`Self::validate_order`] separately.
    #[cfg(test)]
    fn decode(bytes: &[u8]) -> Result<Self> {
        let activity: Self =
            rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("healer activity"))?;
        activity.validate_order()?;
        Ok(activity)
    }
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
fn validate_case_ref(case: &str) -> Result<()> {
    if case.len() != 32
        || !case
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidConfig("invalid healer case ref".into()));
    }
    Ok(())
}
pub(crate) fn proposed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &str,
    now: u64,
) -> Result<()> {
    validate_case_ref(case)?;
    let key = case.to_owned();
    if !ACTIVITY.contains(&vault.store, txn, &key)? {
        ACTIVITY.put(
            &vault.store,
            txn,
            &key,
            &Activity {
                proposed_at: now,
                reviewed_at: None,
                escalated: false,
            },
        )?;
    }
    Ok(())
}
impl Vault {
    /// The host's reviewed-decision door; this records a fact, never applies a
    /// repair. The ordinary consent gate remains the only repair authority.
    pub fn record_healer_review(&self, case: &str, now: u64, escalated: bool) -> Result<()> {
        validate_case_ref(case)?;
        let key = case.to_owned();
        self.with_write_txn(|txn| {
            let mut activity = ACTIVITY
                .get(&self.store, txn, &key)?
                .ok_or(Error::InvalidConfig("unknown healer case".into()))?;
            activity.validate_order()?;
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
            ACTIVITY.put(&self.store, txn, &key, &activity)?;
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
            for (_, activity) in ACTIVITY.scan(&self.store, txn)? {
                activity.validate_order()?;
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
                RECEIPT.put(&self.store, txn, &[kind.tag()], &receipt)?;
                receipts.push(receipt);
            }
            Ok(receipts)
        })
    }
}

#[cfg(test)]
mod tests;
