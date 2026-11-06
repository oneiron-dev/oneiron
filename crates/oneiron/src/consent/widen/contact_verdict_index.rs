//! The (contact, verdict) index over settled contact-disclosure offers
//! (FIX 1338): the once lister used to scan the whole widen table and decode
//! every delta per assembly. This derived index names, per contact and
//! terminal verdict, the proposal references that settled that way. It is a
//! prefilter only: every hit is re-read and revalidated against its base
//! row, and any doubt (flag unset, key/base disagreement, read error) falls
//! back to the full scan in `settled_contact_disclosure_offers_in_txn`.

use super::{StoredProposal, WIDEN_PROPOSALS, WidenDelta, decode_delta, validate_row};
use crate::Vault;
use crate::consent::contact_clearance::ContactDisclosureProposal;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use std::collections::BTreeSet;

/// Keys are `(contact, verdict byte, proposal reference)`; the value is an
/// empty marker. Only the three contact-disclosure verdicts
/// (`ContactDisclosureOutcome::as_str`) are indexed; Bound settlements
/// (`accepted`/`rejected`) never carry a contact offer.
const CONTACT_VERDICT_INDEX: SideTable<(EntityId, [u8; 1], String), (), Raw> =
    SideTable::new(&side_table::CONSENT_WIDEN_CONTACT_VERDICT_INDEX);

/// `Some(1)` once a whole rebuild of the index has committed.
const CONTACT_VERDICT_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::CONSENT_WIDEN_CONTACT_VERDICT_STATE);

const INDEX_VERSION: u64 = 1;

fn verdict_byte(verdict: &str) -> Option<u8> {
    match verdict {
        "once" => Some(1),
        "standing" => Some(2),
        "deny" => Some(3),
        _ => None,
    }
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(
        CONTACT_VERDICT_STATE.get(store, txn, &()),
        Ok(Some(INDEX_VERSION))
    )
}

/// The index key a validated row settles under, when it is a resolved
/// contact-disclosure offer with an indexed verdict.
fn index_key(reference: &str, row: &StoredProposal) -> Option<(EntityId, [u8; 1], String)> {
    if !row.resolved {
        return None;
    }
    let byte = verdict_byte(&row.settlement.as_ref()?.verdict)?;
    let Ok(WidenDelta::ContactDisclosure(offer)) = decode_delta(&row.proposal.canonical_delta)
    else {
        return None;
    };
    Some((offer.offer.contact_ref, [byte], reference.to_owned()))
}

/// Indexes one just-settled row, in the settling transaction.
pub(super) fn index_settled_offer_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    reference: &str,
    row: &StoredProposal,
) -> Result<()> {
    if let Some(key) = index_key(reference, row) {
        CONTACT_VERDICT_INDEX.put(store, txn, &key, &())?;
    }
    Ok(())
}

impl Vault {
    /// Rebuilds the (contact, verdict) index from the stored proposals when
    /// it is missing or stale, in one write transaction (a crash leaves
    /// nothing or everything). Runs at writable open and after a checkpoint
    /// restore (`force`); a complete index is left alone. Rows the scan
    /// skips (unresolved, invalid, Bound) index nothing; store and codec
    /// errors behave per the wrapper below.
    pub(crate) fn backfill_widen_contact_verdict_index(&self, force: bool) -> Result<()> {
        // At open (`force` false) a failed rebuild of this Derived index
        // must never refuse the open (L01 13:15): the flag stays unset and
        // readers keep today's full scan. The restore rebuild (`force`)
        // propagates its errors like its sibling backfills.
        match self.rebuild_widen_contact_verdict_index(force) {
            Err(error) if !force => {
                tracing::warn!(
                    %error,
                    "widen contact-verdict index rebuild failed; settled-offer reads keep the full scan"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn rebuild_widen_contact_verdict_index(&self, force: bool) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if !force && index_complete_in_txn(&self.store, &wtxn) {
            return Ok(());
        }
        let mut keys = Vec::new();
        for (reference, row) in WIDEN_PROPOSALS.scan(&self.store, &*wtxn)? {
            let Ok(row) = validate_row(row, &reference) else {
                continue;
            };
            if let Some(key) = index_key(&reference, &row) {
                keys.push(key);
            }
        }
        CONTACT_VERDICT_INDEX.delete_from(&self.store, &mut wtxn, &[])?;
        for key in &keys {
            CONTACT_VERDICT_INDEX.put(&self.store, &mut wtxn, key, &())?;
        }
        CONTACT_VERDICT_STATE.put(&self.store, &mut wtxn, &(), &INDEX_VERSION)?;
        wtxn.commit()?;
        Ok(())
    }

    /// [`Self::settled_contact_disclosure_offers_in_txn`] narrowed to
    /// `contacts`, served from the index when it is complete. `None` means
    /// any doubt at all: the caller runs the full scan, which answers (or
    /// errors) exactly as it does today. A base row that fails validation
    /// is skipped, as the scan skips it; a key that disagrees with its base
    /// row (missing, unresolved, other verdict, other contact) means the
    /// index is wrong, never a partial answer.
    pub(in crate::consent) fn settled_contact_disclosure_offers_for_contacts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        verdict: &str,
        contacts: &BTreeSet<EntityId>,
    ) -> Result<Option<Vec<(String, ContactDisclosureProposal)>>> {
        let Some(byte) = verdict_byte(verdict) else {
            return Ok(None);
        };
        if !index_complete_in_txn(&self.store, txn) {
            return Ok(None);
        }
        let mut offers = Vec::new();
        for contact in contacts {
            let mut prefix = contact.as_bytes().to_vec();
            prefix.push(byte);
            let rows = match CONTACT_VERDICT_INDEX.scan_from(&self.store, txn, &prefix) {
                Ok(rows) => rows,
                Err(_) => return Ok(None),
            };
            for ((key_contact, key_byte, reference), ()) in rows {
                if key_contact != *contact || key_byte != [byte] || reference.len() != 64 {
                    return Ok(None);
                }
                let row = match WIDEN_PROPOSALS.get(&self.store, txn, &reference) {
                    Ok(Some(row)) => row,
                    _ => return Ok(None),
                };
                let Ok(row) = validate_row(row, &reference) else {
                    continue;
                };
                if !row.resolved
                    || !row
                        .settlement
                        .as_ref()
                        .is_some_and(|settlement| settlement.verdict == verdict)
                {
                    return Ok(None);
                }
                match decode_delta(&row.proposal.canonical_delta) {
                    Ok(WidenDelta::ContactDisclosure(offer))
                        if offer.offer.contact_ref == *contact =>
                    {
                        offers.push((reference, offer));
                    }
                    _ => return Ok(None),
                }
            }
        }
        offers.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Some(offers))
    }
}
