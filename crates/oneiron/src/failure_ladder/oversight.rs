//! Per-vault signed oversight over healer proposals and review decisions.

use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"oneiron:healer-oversight:v1\0";

/// Proposed/reviewed/routed timestamps for one healer case. Key: hex32 (case_ref).
const ACTIVITY: SideTable<String, Activity, Named> = SideTable::new(&side_table::HEALER_ACTIVITY);

/// Latest signed per-vault-device oversight receipt. Key: u8 (OversightKind tag: 0/1/2).
const RECEIPT: SideTable<[u8; 1], OversightReceipt, Named> =
    SideTable::new(&side_table::HEALER_OVERSIGHT_RECEIPT);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Activity {
    proposed_at: u64,
    reviewed_at: Option<u64>,
    escalated: bool,
    /// When the case first reached a person's tray: with its proposal, or
    /// at a review that reached a person. A later answer never clears it.
    escalated_at: Option<u64>,
    /// `Some(true)` while the case is known (its healer was dispatched) and
    /// no proposal of it has persisted: `proposed_at` is then the dispatch
    /// time, and the proposal clock has not started.
    awaiting_proposal: Option<bool>,
    /// `Some(true)` when the case's review was recorded while it awaited its
    /// proposal: `reviewed_at` then predates `proposed_at`, the first
    /// persisted proposal's time, and the review counts with no latency.
    reviewed_before_proposal: Option<bool>,
}

impl Activity {
    fn awaiting(&self) -> bool {
        self.awaiting_proposal == Some(true)
    }

    fn reviewed_early(&self) -> bool {
        self.reviewed_before_proposal == Some(true)
    }

    /// The business rule `Named`'s plain decode cannot enforce: a review cannot predate its
    /// own proposal, unless it was recorded while the case awaited that proposal. Runs
    /// immediately after every decode, direct or through [`ACTIVITY`].
    fn validate_order(&self) -> Result<()> {
        if !self.reviewed_early() && self.reviewed_at.is_some_and(|at| at < self.proposed_at) {
            return Err(Error::CorruptedIndex("healer activity"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversightKind {
    Coverage,
    ReviewLatency,
    EscalationRate,
}
/// The three receipts, in the order builders read them.
const KINDS: [OversightKind; 3] = [
    OversightKind::Coverage,
    OversightKind::ReviewLatency,
    OversightKind::EscalationRate,
];

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
/// Registers `case` as known when its healer is dispatched, without starting
/// its proposal clock: a dispatch is no proposal (FIX 9852). A case already
/// known stays as it is.
pub(crate) fn opened_in_txn(
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
                escalated_at: None,
                awaiting_proposal: Some(true),
                reviewed_before_proposal: None,
            },
        )?;
    }
    Ok(())
}

/// Starts `case`'s proposal clock at `now`, in the write that persists its
/// proposal. The first proposal stands: a later one changes nothing. A
/// review answered while the case awaited it keeps its own time (FIX 10820).
pub(crate) fn proposed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &str,
    now: u64,
) -> Result<()> {
    validate_case_ref(case)?;
    let key = case.to_owned();
    let activity = match ACTIVITY.get(&vault.store, txn, &key)? {
        None => Activity {
            proposed_at: now,
            reviewed_at: None,
            escalated: false,
            escalated_at: None,
            awaiting_proposal: None,
            reviewed_before_proposal: None,
        },
        Some(mut activity) if activity.awaiting() => {
            activity.proposed_at = now.max(activity.proposed_at);
            activity.awaiting_proposal = None;
            activity
        }
        Some(_) => return Ok(()),
    };
    ACTIVITY.put(&vault.store, txn, &key, &activity)
}

/// Records that `case`'s proposal landed in a person's tray, in the write
/// that lands it (FIX 9853). The first route stands, and no later answer
/// clears it. A case with no activity row yet is proposed at `now` too.
pub(crate) fn routed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &str,
    now: u64,
) -> Result<()> {
    validate_case_ref(case)?;
    let key = case.to_owned();
    let mut activity = ACTIVITY.get(&vault.store, txn, &key)?.unwrap_or(Activity {
        proposed_at: now,
        reviewed_at: None,
        escalated: false,
        escalated_at: None,
        awaiting_proposal: None,
        reviewed_before_proposal: None,
    });
    if activity.escalated_at.is_some() {
        return Ok(());
    }
    activity.escalated_at = Some(now.max(activity.proposed_at));
    ACTIVITY.put(&vault.store, txn, &key, &activity)
}
/// Records a person's review of `case` inside the transaction that acts on
/// it (OF-449: an owner's answer to a cleanup proposal). The first review
/// stands: a later one changes nothing. A case with no activity row yet is
/// counted as proposed at `proposed_at`, and a review never predates its
/// proposal, or its dispatch while it awaits one.
pub(crate) fn reviewed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &str,
    proposed_at: u64,
    now: u64,
    escalated: bool,
) -> Result<()> {
    validate_case_ref(case)?;
    let key = case.to_owned();
    let mut activity = ACTIVITY.get(&vault.store, txn, &key)?.unwrap_or(Activity {
        proposed_at,
        reviewed_at: None,
        escalated: false,
        escalated_at: None,
        awaiting_proposal: None,
        reviewed_before_proposal: None,
    });
    if activity.reviewed_at.is_some() {
        return Ok(());
    }
    let at = now.max(activity.proposed_at);
    activity.reviewed_at = Some(at);
    activity.escalated = escalated;
    if escalated && activity.escalated_at.is_none() {
        activity.escalated_at = Some(at);
    }
    if activity.awaiting() {
        activity.reviewed_before_proposal = Some(true);
    }
    ACTIVITY.put(&vault.store, txn, &key, &activity)
}

/// [`reviewed_in_txn`] at `now` for a case whose activity row exists, and
/// nothing for one with none: a healer proposal's own review door counts it
/// under the proposal's id, which only an unbound submission keys (FIX 10821).
pub(crate) fn reviewed_if_known_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &str,
    now: u64,
    escalated: bool,
) -> Result<()> {
    validate_case_ref(case)?;
    if !ACTIVITY.contains(&vault.store, txn, &case.to_owned())? {
        return Ok(());
    }
    reviewed_in_txn(vault, txn, case, now, now, escalated)
}
impl Vault {
    /// The host's reviewed-decision door; this records a fact, never applies a
    /// repair. The ordinary consent gate remains the only repair authority.
    pub fn record_healer_review(&self, case: &str, now: u64, escalated: bool) -> Result<()> {
        validate_case_ref(case)?;
        let key = case.to_owned();
        self.with_write_txn_grouped(|txn| {
            let mut activity = ACTIVITY
                .get(&self.store, txn, &key)?
                .ok_or(Error::InvalidConfig("unknown healer case".into()))?;
            activity.validate_order()?;
            // An early review's retry is answered as any recorded review's is.
            if now < activity.proposed_at && !activity.reviewed_early() {
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
            if escalated && activity.escalated_at.is_none() {
                activity.escalated_at = Some(now);
            }
            if activity.awaiting() {
                activity.reviewed_before_proposal = Some(true);
            }
            ACTIVITY.put(&self.store, txn, &key, &activity)?;
            Ok(())
        })
    }
    /// Stores a healer case's activity as given, without the order check the
    /// doors keep, so a test can hold a vault whose stored activity no longer
    /// reads back valid.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn put_healer_activity_for_test(
        &self,
        case: &str,
        proposed_at: u64,
        reviewed_at: Option<u64>,
    ) -> Result<()> {
        validate_case_ref(case)?;
        let activity = Activity {
            proposed_at,
            reviewed_at,
            escalated: false,
            escalated_at: None,
            awaiting_proposal: None,
            reviewed_before_proposal: None,
        };
        self.with_write_txn_grouped(|txn| {
            ACTIVITY.put(&self.store, txn, &case.to_owned(), &activity)
        })
    }
    /// Emits all three receipts in one transaction. Each contains counts so
    /// empty denominators remain explicit instead of yielding NaN rates.
    pub fn emit_healer_oversight(&self, now: u64) -> Result<Vec<OversightReceipt>> {
        self.prepare_install_signing()?;
        self.with_write_txn_grouped(|txn| {
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
                // A dispatched case no proposal of it has persisted is not
                // proposed, reviewed or not (FIX 9852, 10820).
                if activity.proposed_at > now || activity.awaiting() {
                    continue;
                }
                counts.proposed = counts.proposed.saturating_add(1);
                if let Some(at) = activity.reviewed_at.filter(|at| *at <= now) {
                    counts.reviewed = counts.reviewed.saturating_add(1);
                    // A review recorded before its proposal persisted waited
                    // for nothing.
                    counts.review_latency_secs = counts
                        .review_latency_secs
                        .saturating_add(at.saturating_sub(activity.proposed_at));
                }
                // Routing to a person counts when it happened, reviewed or
                // not (FIX 9853); a row from before the route was kept
                // counts its review's escalation as before.
                let routed = activity
                    .escalated_at
                    .or(activity.reviewed_at.filter(|_| activity.escalated));
                if routed.is_some_and(|at| at <= now) {
                    counts.escalated = counts.escalated.saturating_add(1);
                }
            }
            let mut receipts = Vec::new();
            for kind in KINDS {
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
    /// The latest receipts [`Vault::emit_healer_oversight`] stored, coverage
    /// first, then latency, then escalation rate, each paired with whether it
    /// verifies against this vault device's own signing key. Empty until the
    /// host first emits. A read transaction only: the read never waits for
    /// the writer.
    pub fn healer_oversight_receipts(&self) -> Result<Vec<(OversightReceipt, bool)>> {
        let txn = self.store.env.read_txn()?;
        let stored = KINDS
            .into_iter()
            .filter_map(|kind| RECEIPT.get(&self.store, &txn, &[kind.tag()]).transpose())
            .collect::<Result<Vec<_>>>()?;
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        // Emission mints the identity in the transaction that stores the
        // receipts. Without a key, no receipt verifies.
        let signer = crate::identity::read_device_verifying_key_in_txn(self, &txn)?;
        Ok(stored
            .into_iter()
            .map(|receipt| {
                let verified = signer.is_some_and(|signer| receipt.verify(&signer));
                (receipt, verified)
            })
            .collect())
    }
}
