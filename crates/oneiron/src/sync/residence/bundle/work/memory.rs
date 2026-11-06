//! Allocation sizing only. Strict acceptance still uses the unchanged native
//! sealed-object validators. This scan keeps one upload part, not a full object.
use super::*;

fn room(bytes: u64, envelopes: u64) -> u64 {
    use oneiron_crypto::{Envelope, MAX_ID_LEN, MLKEM1024_CIPHERTEXT_LEN, ONEV_HEADER_PREFIX_MAX};
    let metadata = (std::mem::size_of::<Record>() as u64 + 2 * super::super::STAGE_LEN as u64)
        .saturating_mul(4);
    let page = (STORED_PART as u64)
        .saturating_mul(2)
        .saturating_add((super::super::SEALED_BUNDLE_PUT_PART_MAX as u64).saturating_mul(2));
    // Header::decode owns three bounded ids, the24-byte nonce, and at most
    // one ML-KEM box. Header::encode starts at128 and doubles, bounded by
    // next_power_of_two(MAX). Ciphertext totals fit one source length.
    let header_heap = (3 * MAX_ID_LEN
        + 24
        + MLKEM1024_CIPHERTEXT_LEN
        + ONEV_HEADER_PREFIX_MAX.next_power_of_two()) as u64;
    // Source, SealedObject's clone, and all parsed ciphertext. Frame vectors
    // grow geometrically; ten extra slots cover initial capacities/current
    // not-yet-pushed envelopes. The vault-id scratch fits the page allowance.
    bytes
        .saturating_mul(3)
        .saturating_add(envelopes.saturating_mul(header_heap))
        .saturating_add(
            envelopes
                .saturating_mul(2)
                .saturating_add(10)
                .saturating_mul(std::mem::size_of::<Envelope>() as u64),
        )
        .saturating_add(page)
        .saturating_add(metadata)
}

fn maximum_envelopes(bytes: u64) -> u64 {
    bytes / (4 + oneiron_crypto::ONEV_HEADER_PREFIX_MIN + oneiron_crypto::TAG_LEN) as u64
}

/// A conservative fallback for unreadable/malformed frame counts, and the
/// copy/cleanup room when no whole-object validation is due. Never a cap.
#[must_use]
pub fn sealed_bundle_work_memory_bytes(bytes: u64) -> u64 {
    room(bytes, maximum_envelopes(bytes))
}

struct Counts<'a, 'env> {
    vault: &'a Vault,
    txn: &'a heed::RoTxn<'env>,
    prefix: String,
    start: u64,
    part: Vec<u8>,
    total: u64,
}

impl Counts<'_, '_> {
    fn read<const N: usize>(&mut self, at: u64) -> Result<Option<[u8; N]>> {
        let Some(end) = at.checked_add(N as u64).filter(|end| *end <= self.total) else {
            return Ok(None);
        };
        let mut out = [0; N];
        let mut copied = 0;
        let mut cursor = at;
        while cursor < end {
            while self.part.is_empty()
                || cursor >= self.start.saturating_add(self.part.len() as u64)
            {
                if !self.part.is_empty() {
                    self.start += self.part.len() as u64;
                }
                let key = format!("{}{:016x}", self.prefix, self.start);
                self.part = match STAGE_PARTS.get_bytes(&self.vault.store, self.txn, &key)? {
                    Some(part) if !part.is_empty() => part,
                    _ => return Ok(None),
                };
            }
            let from = usize::try_from(cursor.saturating_sub(self.start))
                .map_err(|_| Error::InvalidKey)?;
            let take = (N - copied).min(self.part.len() - from);
            out[copied..copied + take].copy_from_slice(&self.part[from..from + take]);
            copied += take;
            cursor += take as u64;
        }
        Ok(Some(out))
    }
}

fn count_in(vault: &Vault, txn: &heed::RoTxn<'_>, source: &Source, total: u64) -> Result<u64> {
    let fallback = maximum_envelopes(total);
    let mut cursor = Counts {
        vault,
        txn,
        prefix: stage_parts_prefix(&stage_identity(&source.header)?),
        start: 0,
        part: Vec::new(),
        total,
    };
    // magic4/version1/generation24, u16 capsule count, each u32-counted
    // capsule, then u32 body-part count. No envelope is parsed or accepted.
    let Some(slots) = cursor.read::<2>(29)? else {
        return Ok(fallback);
    };
    let slots = u16::from_be_bytes(slots) as u64;
    let mut at = 31u64;
    for _ in 0..slots {
        let Some(len) = cursor.read::<4>(at)? else {
            return Ok(fallback);
        };
        let Some(next) = at
            .checked_add(4)
            .and_then(|at| at.checked_add(u32::from_be_bytes(len) as u64))
            .filter(|at| *at <= total)
        else {
            return Ok(fallback);
        };
        at = next;
    }
    let Some(parts) = cursor.read::<4>(at)? else {
        return Ok(fallback);
    };
    Ok(slots
        .saturating_add(u32::from_be_bytes(parts) as u64)
        .min(fallback))
}

/// Read on a tracked blocking worker under the small scan-memory hold. Both
/// objects are sized so a concurrent attachment advancing the phase cannot
/// make the reserved validation room smaller than the phase actually run.
pub fn sealed_bundle_work_memory_room(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    let record = load_in(vault, &txn, &id)?.ok_or_else(denied)?;
    bound_in(vault, &txn, peer, &record)?;
    if !matches!(record.phase, Phase::ValidateBundle | Phase::ValidatePads) {
        return Ok(room(0, 0));
    }
    let mut bytes = room(0, 0);
    for index in 0..2 {
        let total = record.stage(index)?.total;
        bytes = bytes.max(room(
            total,
            count_in(vault, &txn, &record.sources[index], total)?,
        ));
    }
    Ok(bytes)
}
