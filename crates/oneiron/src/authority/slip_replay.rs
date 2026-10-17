//! Bounded, timestamp-bound replay windows for authenticated slip requests.
use super::invalid_authority;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::{Vault, VaultWriterLease};

/// How far, either way, a proof's signed timestamp may sit from the vault's
/// proof clock ([`request_now_in_txn`]).
const WINDOW_SECS: u64 = 60;

/// A nonce row is kept until the proof clock is a day past its signed time,
/// not just past the window. A host clock that runs ahead and is set back
/// within a day leaves every proof admitted meanwhile on record, so an owner
/// clock recovery can lower the proof clock without reopening any of them.
const RETAIN_SECS: u64 = 24 * 60 * 60;

/// The proof clock's floor. Absent until the first admission that commits
/// it; until then the vault's recording-clock floor, which earlier
/// admissions committed, stands in.
const PROOF_CLOCK_FLOOR: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::AUTHORITY_SLIP_PROOF_CLOCK);

/// No proof signed earlier is admitted, whatever the window says.
const PROOF_NOT_BEFORE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::AUTHORITY_SLIP_PROOF_NOT_BEFORE);

/// The clock a holder proof is judged on, as one transaction reads it.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProofClock {
    /// Wall time, held at or above the proof clock's committed floor.
    now: u64,
    /// Past every proof whose nonce row is gone, and at least the wall time
    /// of the last owner clock recovery.
    not_before: u64,
}

impl ProofClock {
    #[cfg(test)]
    pub(super) fn at(now: u64) -> Self {
        Self { now, not_before: 0 }
    }
}

/// The proof clock's floor in `txn`.
fn proof_floor_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u64> {
    match PROOF_CLOCK_FLOOR.get(&vault.store, txn, &())? {
        Some(floor) => Ok(floor),
        None => crate::ports::authorization_floor_in_txn(&vault.store, txn),
    }
}

/// The clock a holder proof's freshness is judged on, read without moving
/// it: wall time, held at or above the floor admissions have committed. A
/// holder signs on its own wall clock, so the window compares wall time with
/// wall time. The authority clock stays the clock of slip lifetimes and
/// authority facts; it does not count time the vault was closed or its host
/// asleep, so a window judged on it refused every proof once that time
/// passed 60 s. The proof clock has its own floor rather than the vault's
/// recording clock, so an owner can recover it from a host clock that ran
/// ahead ([`Vault::recover_proof_clock`]) while every recorded stamp keeps
/// its order.
pub(super) fn request_now_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProofClock> {
    Ok(ProofClock {
        now: proof_floor_in_txn(vault, txn)?.max(vault.store.clock.wall_now()),
        not_before: PROOF_NOT_BEFORE.get(&vault.store, txn, &())?.unwrap_or(0),
    })
}

/// [`request_now_in_txn`] for the transaction that admits a proof. The
/// reading is committed as the proof clock's floor beside the nonce row, so
/// a wall clock that later steps back cannot reopen a proof whose row this
/// reading evicted. The vault's recording clock observes the admission as
/// well, as it did before proofs had a clock of their own, so every reader
/// of that clock sees the same floor after a reopen.
pub(super) fn admission_now_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<ProofClock> {
    crate::ports::observe_clock_floor_in_txn(&vault.store, txn)?;
    let clock = request_now_in_txn(vault, txn)?;
    if PROOF_CLOCK_FLOOR.get(&vault.store, txn, &())? != Some(clock.now) {
        PROOF_CLOCK_FLOOR.put(&vault.store, txn, &(), &clock.now)?;
    }
    Ok(clock)
}

/// What an owner clock recovery found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofClockRecovery {
    /// The proof clock now reads wall time again. Every proof signed before
    /// `not_before` stays refused, which covers every proof this vault has
    /// forgotten; a later proof the vault admitted before keeps its nonce row.
    Recovered {
        old_floor: u64,
        new_floor: u64,
        not_before: u64,
    },
    /// Wall time is at or past the floor: nothing to recover.
    NotAhead { floor: u64, wall: u64 },
    /// Nonce rows of proofs signed up to `forgotten_before` are gone: the
    /// host clock stayed ahead for over a day while proofs were admitted, or
    /// admissions that kept rows for the window only admitted them. Every
    /// proof signed before `forgotten_before` stays refused, and that is
    /// still past the window around `wall`, so lowering the clock would let
    /// no fresh proof in. Nothing changed; fresh proofs get in once wall
    /// time reaches `floor`.
    Forgotten {
        floor: u64,
        forgotten_before: u64,
        wall: u64,
    },
}

/// A proof the window refused only because the proof clock sits ahead of
/// the host's wall clock: on the wall clock it is fresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofClockAhead {
    pub floor: u64,
    pub wall: u64,
}

impl Vault {
    /// Lowers the clock holder proofs are judged on to the host's wall
    /// clock, after the host clock ran ahead and was set back. An owner act
    /// on a stopped vault: this process must hold the vault's writer lease.
    ///
    /// No proof the vault admitted before is admitted again. A proof whose
    /// nonce row is gone was signed before the committed `not_before`, which
    /// rises to at least the recovery's wall time; every other admitted proof
    /// keeps its row. When the vault forgot a proof signed past that wall
    /// time's window, no fresh proof could get in either, so the act refuses
    /// ([`ProofClockRecovery::Forgotten`]). The recording clock and every
    /// stamp on it are left as they are.
    pub fn recover_proof_clock(&self, owner: &AuthenticatedOwner) -> Result<ProofClockRecovery> {
        if !self
            .writer_lease()
            .is_some_and(VaultWriterLease::held_by_current_process)
        {
            return Err(Error::ConcurrentWrite(
                "clock recovery needs this process to hold the vault's writer lease",
            ));
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let floor = proof_floor_in_txn(self, &txn)?;
        let wall = self.store.clock.wall_now();
        if wall >= floor {
            return Ok(ProofClockRecovery::NotAhead { floor, wall });
        }
        let forgotten_before = match PROOF_NOT_BEFORE.get(&self.store, &txn, &())? {
            Some(not_before) => not_before,
            None => {
                let oldest = match REPLAY_NONCE.iter_from(&self.store, &txn, &[])?.next() {
                    Some(row) => Some(row?.0.timestamp),
                    None => None,
                };
                unmarked_not_before(oldest, floor)
            }
        };
        if forgotten_before > wall.saturating_add(WINDOW_SECS) {
            return Ok(ProofClockRecovery::Forgotten {
                floor,
                forgotten_before,
                wall,
            });
        }
        let not_before = forgotten_before.max(wall);
        PROOF_CLOCK_FLOOR.put(&self.store, &mut txn, &(), &wall)?;
        PROOF_NOT_BEFORE.put(&self.store, &mut txn, &(), &not_before)?;
        txn.commit()?;
        Ok(ProofClockRecovery::Recovered {
            old_floor: floor,
            new_floor: wall,
            not_before,
        })
    }

    /// `Some` when the window refuses this request only because the proof
    /// clock sits ahead of the host's wall clock: the lockout
    /// [`Self::recover_proof_clock`] lifts. On the wall clock, the admission
    /// door would take the request now: it verifies in full, as
    /// [`Self::verify_logged_capability_slip_request`] checks it, against
    /// `not_before` as it stands, carries a slip the transport doors take
    /// (not a one-shot one), and its nonce is unused. So a forged, stale,
    /// replayed or refused request learns nothing of the clock.
    ///
    /// It speaks for authentication, and for the holder's next proof: no
    /// proof signed before a recovery gets in after it, so this one never
    /// does, and a route's own authorization still answers once a request
    /// gets in. Returns the slip as verified on the wall clock, for a
    /// transport's own checks of what it takes.
    pub fn proof_clock_ahead(
        &self,
        slip: &super::CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<Option<(ProofClockAhead, super::VerifiedSlip)>> {
        let txn = self.store.env.read_txn()?;
        let clock = request_now_in_txn(self, &txn)?;
        let wall = self.store.clock.wall_now();
        if clock.now <= wall || clock.now.abs_diff(timestamp) <= WINDOW_SECS {
            return Ok(None);
        }
        let on_wall = ProofClock { now: wall, ..clock };
        let Ok(challenge) = request_challenge(timestamp, nonce, on_wall) else {
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let Some(mint) = fold.slips.mints.get(&slip.claims.slip_id) else {
            return Ok(None);
        };
        let now = self.instant_in_txn(&txn)?.secs();
        let Ok(verified) = slip.verify(&mint.signer, &fold, now, &challenge, signature) else {
            return Ok(None);
        };
        if self
            .require_live_slip_grant_in_txn(&txn, verified.claims(), now)
            .is_err()
        {
            return Ok(None);
        }
        if verified.claims().single_use {
            return Ok(None);
        }
        // A proof the vault admitted before stays refused on any clock.
        let admitted = nonce_key(&verified.claims().binding_key, nonce, timestamp);
        if REPLAY_NONCE.contains(&self.store, &txn, &admitted)? {
            return Ok(None);
        }
        Ok(Some((
            ProofClockAhead {
                floor: clock.now,
                wall,
            },
            verified,
        )))
    }
}

/// Refuses to publish `replacement`, a restore made for `vault`'s place,
/// when `vault`'s holder-proof freshness moved after the replacement carried
/// it: a nonce row, the proof clock's floor or `not_before`. The replacement
/// would not know a proof `vault` admitted since, nor an owner clock
/// recovery's mark, so a proof refused here would get in there. Read in
/// `txn`, under `vault`'s writer, before the swap.
pub(crate) fn refuse_moved_proof_freshness(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    replacement: &Vault,
) -> Result<()> {
    let their_txn = replacement.store.env.read_txn()?;
    let mut same = PROOF_CLOCK_FLOOR.get(&vault.store, txn, &())?
        == PROOF_CLOCK_FLOOR.get(&replacement.store, &their_txn, &())?
        && PROOF_NOT_BEFORE.get(&vault.store, txn, &())?
            == PROOF_NOT_BEFORE.get(&replacement.store, &their_txn, &())?;
    let mut ours_rows = REPLAY_NONCE.iter_from(&vault.store, txn, &[])?;
    let mut their_rows = REPLAY_NONCE.iter_from(&replacement.store, &their_txn, &[])?;
    while same {
        match (
            ours_rows.next().transpose()?,
            their_rows.next().transpose()?,
        ) {
            (None, None) => break,
            (Some((ours, ())), Some((theirs, ()))) => {
                same = ours.timestamp == theirs.timestamp && ours.digest_hex == theirs.digest_hex;
            }
            _ => same = false,
        }
    }
    if same {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "this vault admitted agent requests or recovered its proof clock after the restore \
             was prepared; prepare it again"
                .into(),
        ))
    }
}

/// Key of one admitted replay-nonce marker: the signed timestamp as 16 lowercase hex digits,
/// then `:`, then the keyed digest of (binding key + nonce) as 64 lowercase hex digits — the
/// pre-migration `{timestamp:016x}:{digest_hex}` spelling, minus the shared prefix the table
/// now carries.
struct NonceKey {
    timestamp: u64,
    digest_hex: String,
}

impl SideKey for NonceKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(format!("{:016x}", self.timestamp).as_bytes());
        out.push(b':');
        out.extend_from_slice(self.digest_hex.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (ts_hex, digest_hex) = text.split_once(':')?;
        if ts_hex.len() != 16 || digest_hex.len() != 64 {
            return None;
        }
        Some(Self {
            timestamp: u64::from_str_radix(ts_hex, 16).ok()?,
            digest_hex: digest_hex.to_owned(),
        })
    }
}

/// The row an admitted proof leaves: its signed time, and the keyed digest of
/// the binding key and nonce.
fn nonce_key(binding_key: &[u8; 32], nonce: &[u8], timestamp: u64) -> NonceKey {
    let mut material = binding_key.to_vec();
    material.extend_from_slice(nonce);
    NonceKey {
        timestamp,
        digest_hex: blake3::hash(&material).to_hex().to_string(),
    }
}

/// Admitted request nonce, kept until the proof clock is a day past its signed time (empty
/// marker). Key: u64hex16 ":" hex64.
const REPLAY_NONCE: SideTable<NonceKey, (), Raw> =
    SideTable::new(&side_table::AUTHORITY_SLIP_REPLAY_NONCE);

/// The timestamp is part of the signed challenge, never an unsigned eviction hint.
pub(super) fn request_challenge(
    timestamp: u64,
    nonce: &[u8],
    clock: ProofClock,
) -> Result<Vec<u8>> {
    if clock.now.abs_diff(timestamp) > WINDOW_SECS
        || timestamp < clock.not_before
        || nonce.len() != 32
        || !nonce
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(invalid_authority());
    }
    let nonce = std::str::from_utf8(nonce).map_err(|_| invalid_authority())?;
    Ok(holder_proof_challenge(timestamp, nonce))
}

/// The challenge a slip holder signs, through the slip's binding transcript,
/// to prove it holds the binding key.
#[must_use]
pub fn holder_proof_challenge(timestamp: u64, nonce: &str) -> Vec<u8> {
    format!("oneiron-request:{timestamp}:{nonce}").into_bytes()
}

/// A fresh holder proof for one request: a new nonce, signed through the
/// slip's binding transcript with the connection key. The proof is not a
/// replacement bearer token.
pub fn holder_proof(
    slip: &super::CapabilitySlip,
    key: &ed25519_dalek::SigningKey,
    timestamp: u64,
) -> Result<serde_json::Value> {
    use ed25519_dalek::Signer;
    let nonce = crate::EntityId::now().to_hex();
    let transcript = slip.binding_transcript(&holder_proof_challenge(timestamp, &nonce))?;
    let signature = super::slip::hex(&key.sign(&transcript).to_bytes());
    Ok(serde_json::json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}))
}

/// `not_before` for a vault whose admissions kept no mark, judged on a
/// clock at `now` that never ran back. Those admissions evicted only rows
/// signed a window before their clock, and before every row they kept, so
/// each evicted proof was signed before the oldest row left and before
/// `now` less the window. With no row left, none was ever admitted.
fn unmarked_not_before(oldest: Option<u64>, now: u64) -> u64 {
    oldest.map_or(0, |oldest| oldest.min(now.saturating_sub(WINDOW_SECS)))
}

/// One row per admitted proof, keyed by its signed timestamp. The timestamp
/// bounds the table: rows signed a day before the proof clock are evicted in
/// the same transaction, and a crowded table admits every fresh proof.
pub(super) fn record_nonce(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding_key: &[u8; 32],
    nonce: &[u8],
    timestamp: u64,
    clock: ProofClock,
) -> Result<()> {
    request_challenge(timestamp, nonce, clock)?;
    // An evicted proof already fails `request_challenge`, and `clock.now`
    // never runs back (callers pass `admission_now_in_txn`, committed with
    // this row). Only an owner clock recovery lowers it, so `not_before`
    // rises past every evicted row in this transaction, and no lowered clock
    // reopens one.
    let floor = clock.now.saturating_sub(RETAIN_SECS);
    let mut oldest = None;
    let mut expired = Vec::new();
    for row in REPLAY_NONCE.iter_from(&vault.store, txn, &[])? {
        let (key, ()) = row?;
        oldest.get_or_insert(key.timestamp);
        if key.timestamp >= floor {
            break;
        }
        expired.push(key);
    }
    // The first admission under this rule writes the mark, so an absent one
    // only ever means admissions that kept none.
    let kept = PROOF_NOT_BEFORE.get(&vault.store, txn, &())?;
    let mut not_before = kept.unwrap_or_else(|| unmarked_not_before(oldest, clock.now));
    if let Some(newest) = expired.last() {
        not_before = not_before.max(newest.timestamp.saturating_add(1));
    }
    if kept != Some(not_before) {
        PROOF_NOT_BEFORE.put(&vault.store, txn, &(), &not_before)?;
    }
    for key in expired {
        REPLAY_NONCE.delete(&vault.store, txn, &key)?;
    }
    let key = nonce_key(binding_key, nonce, timestamp);
    if REPLAY_NONCE.contains(&vault.store, txn, &key)? {
        return Err(invalid_authority());
    }
    REPLAY_NONCE.put(&vault.store, txn, &key, &())?;
    Ok(())
}

#[cfg(test)]
mod tests;
