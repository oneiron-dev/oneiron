//! An xz file's payload: the stream decoded whole, its checks verified and
//! nothing left after the last stream (FIX 2471). The rebuilt copy re-encodes
//! the masked payload with default options.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::{Budget, Walked, encode_failed, over_budget, unreadable};
use crate::secret_custody::MemberStep;

fn payload(bytes: &[u8], budget: &mut Budget) -> Walked<Zeroizing<Vec<u8>>> {
    let limit = budget.limit();
    let mut payload = Zeroizing::new(Vec::new());
    // One byte past the limit is enough to tell a payload past it.
    lzma_rust2::XzReader::new(bytes, true)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut *payload)
        .map_err(|_| unreadable())?;
    if payload.len() > limit {
        return Err(over_budget());
    }
    budget.spend(payload.len())?;
    Ok(payload)
}

pub(super) fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let payload = payload(bytes, budget)?;
    each(MemberStep::Xz, &payload, budget)
}

pub(super) fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let payload = payload(bytes, budget)?;
    let masked = each(MemberStep::Xz, &payload, budget)?.unwrap_or_else(|| payload.to_vec());
    let mut encoder =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::default())
            .map_err(|_| encode_failed())?;
    encoder.write_all(&masked).map_err(|_| encode_failed())?;
    encoder.finish().map_err(|_| encode_failed())
}
