//! The owner's pick between two frozen responses (ARCH-0053 #judge-swap,
//! FIX 2797): which of a blind preference pair's two responses is better.
//!
//! A blind preference pair is two held-out receipts' responses, named by
//! its `pair_ref` (`first|second`, the two receipts). The owner's pick on
//! that pair is the settled outcome of every judge-swap disagreement that
//! asked about it: the judge that preferred the picked response sides with
//! the outcome. A pick is final, like every calibration label: the same pick
//! again returns it, another one fails. The responses are the receipts' own
//! results, which never change, so the pick stays bound to what was shown.

use serde::{Deserialize, Serialize};

use super::PreferredResponse;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// Owner picks, by pair reference.
const RESPONSE_PAIR: SideTable<String, ResponsePairPick, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_RESPONSE_PAIR);

/// Longest pair reference kept, as a blind preference bounds it.
const MAX_PAIR_REF_BYTES: usize = 256;

/// The owner's pick on one blind preference pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePairPick {
    pub pair_ref: String,
    pub preferred: PreferredResponse,
    /// The person who picked, 32 hex.
    pub by: String,
    /// Unix seconds.
    pub picked_at: u64,
}

/// Records the owner's pick on `pair_ref`, once.
///
/// # Errors
///
/// A credential that no longer names a live owner; a pair reference that is
/// not two distinct receipts joined by `|` within 256 bytes; a pick that
/// differs from the one already recorded; storage errors.
pub fn pick_response_pair(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    pair_ref: &str,
    preferred: PreferredResponse,
    at: u64,
) -> Result<ResponsePairPick> {
    let by = owner.revalidate_person(vault)?;
    let well_formed = pair_ref.len() <= MAX_PAIR_REF_BYTES
        && !pair_ref.contains('\0')
        && pair_ref.split_once('|').is_some_and(|(first, second)| {
            !first.is_empty() && !second.is_empty() && first != second
        });
    if !well_formed {
        return Err(Error::InvalidClaimBody(
            "a pair reference is two distinct receipts joined by |",
        ));
    }
    let key = pair_ref.to_owned();
    vault.with_write_txn_grouped(|txn| {
        if let Some(previous) = RESPONSE_PAIR.get(&vault.store, &*txn, &key)? {
            if previous.preferred != preferred {
                return Err(Error::InvalidClaimBody(
                    "a pair's pick is final; another pick fails",
                ));
            }
            return Ok(previous);
        }
        let pick = ResponsePairPick {
            pair_ref: key.clone(),
            preferred,
            by: by.to_hex(),
            picked_at: at,
        };
        RESPONSE_PAIR.put(&vault.store, txn, &key, &pick)?;
        Ok(pick)
    })
}

/// Every owner pick, in pair-reference order.
///
/// # Errors
///
/// Storage errors.
pub fn response_pair_picks(vault: &Vault) -> Result<Vec<ResponsePairPick>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(RESPONSE_PAIR
        .scan_from(&vault.store, &rtxn, &[])?
        .into_iter()
        .map(|(_, pick)| pick)
        .collect())
}

/// The owner's pick on `pair_ref`, if one stands.
pub(crate) fn response_pair_pick(
    vault: &Vault,
    pair_ref: &str,
) -> Result<Option<PreferredResponse>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(RESPONSE_PAIR
        .get(&vault.store, &rtxn, &pair_ref.to_owned())?
        .map(|pick| pick.preferred))
}
