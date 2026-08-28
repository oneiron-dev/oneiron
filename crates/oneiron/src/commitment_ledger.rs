//! Counterparty commitment ledger projection (CMT-5).
//!
//! One read-side question answered over CMT-1's `commitment.record` claims:
//! given an OF-347 CounterpartyContact, what does that counterparty still owe,
//! and what is still owed to them. Both sides come back due-sorted.
//!
//! The projection stores nothing and indexes nothing — it walks the existing
//! `ENTITY_TYPE_CLAIM` type-index under one read transaction. It also reads no
//! schedule: [`CommitmentRecord::schedule`] stays the opaque CMT-1 payload, so
//! a later expanded series instance arrives here as an ordinary
//! `commitment.record` claim carrying its own bitemporal valid-time and needs
//! no change on this side.
//!
//! The contact join is explicit rather than parsed. A CounterpartyContact
//! names the external counterparty; the ChannelIdentity it points at names the
//! LOCAL channel the contact was reached on. The commitment endpoint is the
//! CounterpartyContact entity id itself, never the `counterparty` string.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, claim_surfaceable, decode_claim_body};
use crate::commitment::{
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, PREDICATE_COMMITMENT_RECORD,
    decode_commitment_claim,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

/// The counterparty a ledger is drawn for: the contact row, the channel
/// identity it is bound to, and that identity's local addressing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentLedgerCounterparty {
    /// CounterpartyContact entity id. This is also the commitment endpoint
    /// that obligor/beneficiary references are matched against.
    pub contact_ref: EntityId,
    /// ChannelIdentity the contact is bound to.
    pub identity_ref: EntityId,
    /// External counterparty address/handle, exactly as the contact stores it.
    pub counterparty: String,
    /// Channel of the bound local identity.
    pub channel: String,
    /// Local address or handle of the bound identity.
    pub address_or_handle: String,
}

/// One open commitment on a counterparty ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitmentLedgerEntry {
    /// CLAIM entity id of the `commitment.record` row.
    pub commitment_id: EntityId,
    /// Bitemporal valid-time of the obligation. This is the due key.
    pub valid_time: TimeRange,
    /// Transaction-time the row was learned. Metadata only — it never
    /// participates in due order.
    pub learned_at: u64,
    /// Decoded CMT-1 record. Its `schedule` stays opaque here.
    pub record: CommitmentRecord,
}

/// Two-way open-commitment ledger for one counterparty contact.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitmentLedger {
    /// Resolved contact + channel identity join.
    pub counterparty: CommitmentLedgerCounterparty,
    /// Open commitments the counterparty owes: a `third_party` obligor whose
    /// `entity_ref` is this contact.
    pub owed_by_them: Vec<CommitmentLedgerEntry>,
    /// Open commitments owed TO the counterparty: this contact is the
    /// beneficiary, whoever the obligor is.
    pub owed_to_them: Vec<CommitmentLedgerEntry>,
}

impl Vault {
    /// Projects the two-way open-commitment ledger for one CounterpartyContact.
    ///
    /// Only SURFACEABLE, lifecycle-`Active`, non-stale `commitment.record`
    /// claims whose decoded status is [`CommitmentStatus::Open`] enter the
    /// ledger. Proposed, stale, fulfilled, released, lapsed and superseded
    /// commitments stay point-readable through CMT-1's
    /// [`Vault::get_commitment_claim`] — they are simply not open obligations.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] when no contact row exists under
    /// `contact_ref`, [`Error::InvalidEntityType`] when that id names a
    /// different entity kind, and
    /// `Error::CorruptedIndex("counterparty contact channel identity")` when
    /// the contact's `identity_ref` dangles — a broken join is a corrupted
    /// vault, not an empty ledger.
    pub fn commitment_ledger_for_counterparty(
        &self,
        contact_ref: &EntityId,
    ) -> Result<CommitmentLedger> {
        let contact = self
            .get_counterparty_contact(contact_ref)?
            .ok_or(Error::EntityNotFound)?;
        let identity = self
            .get_channel_identity(&contact.identity_ref)?
            .ok_or(Error::CorruptedIndex("counterparty contact channel identity"))?;

        let (mut owed_by_them, mut owed_to_them) = self.project_commitment_rows(contact_ref)?;
        sort_due(&mut owed_by_them);
        sort_due(&mut owed_to_them);

        Ok(CommitmentLedger {
            counterparty: CommitmentLedgerCounterparty {
                contact_ref: *contact_ref,
                identity_ref: contact.identity_ref,
                counterparty: contact.counterparty,
                channel: identity.channel,
                address_or_handle: identity.address_or_handle,
            },
            owed_by_them,
            owed_to_them,
        })
    }

    /// Walks the CLAIM type-index once and splits the admitted open
    /// commitments into `(owed_by_them, owed_to_them)`, unsorted.
    fn project_commitment_rows(
        &self,
        contact_ref: &EntityId,
    ) -> Result<(Vec<CommitmentLedgerEntry>, Vec<CommitmentLedgerEntry>)> {
        let rtxn = self.store.env.read_txn()?;
        let mut owed_by_them = Vec::new();
        let mut owed_to_them = Vec::new();

        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CLAIM])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("claim type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("claim type index"));
            }

            // TOLERATE-SKIP. Every CLAIM in the vault passes under this cursor,
            // and a row this projection cannot decode is some other predicate's
            // problem — refusing here would let one unrelated body take the
            // whole ledger down. Reserved predicates are read-allowed for the
            // same reason: unrelated rows legitimately carry them.
            let Ok(body) = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
                continue;
            };
            // EXACT predicate, not a `commitment.` prefix: adopting every
            // future commitment predicate into this decoder is how a read side
            // silently starts fail-closing on rows it was never asked about.
            if body.predicate != PREDICATE_COMMITMENT_RECORD {
                continue;
            }
            // FAIL-CLOSED, now that the row is known to be ours: a
            // `commitment.record` claim that will not decode is a typed error,
            // never a silent omission from an obligation ledger.
            let record = decode_commitment_claim(&body)?.ok_or(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ))?;

            if !claim_surfaceable(&body) || record.status != CommitmentStatus::Open {
                continue;
            }

            // The two directions are independent tests, not a match. Owner- and
            // Agent-owed commitments are OURS to keep even when their
            // `entity_ref` happens to equal the contact id, so only a
            // `third_party` obligor can put a row on the owed-by side.
            let owed_by = record.obligor.kind == CommitmentObligorKind::ThirdParty
                && record.obligor.entity_ref == *contact_ref;
            let owed_to = record.beneficiary == *contact_ref;
            if !owed_by && !owed_to {
                continue;
            }

            let ledger_entry = CommitmentLedgerEntry {
                commitment_id: id,
                valid_time: ledger_valid_time(&body)?,
                learned_at: header.learned_at,
                record,
            };

            // A counterparty who owes themselves belongs on BOTH sides. There
            // is no direction precedence to apply, and collapsing the row would
            // hide half of what it says.
            if owed_by && owed_to {
                owed_by_them.push(ledger_entry.clone());
                owed_to_them.push(ledger_entry);
            } else if owed_by {
                owed_by_them.push(ledger_entry);
            } else {
                owed_to_them.push(ledger_entry);
            }
        }

        Ok((owed_by_them, owed_to_them))
    }
}

/// Reads the due window off an ADMITTED commitment claim.
///
/// CMT-1's structural validator already refuses to store a `commitment.record`
/// claim without both bounds, so on a healthy vault this never fails. It is
/// still fail-closed rather than defaulted: the read path decodes bodies
/// WITHOUT re-running family validation, so a foreign or damaged row could
/// arrive here half-bounded, and an obligation with a guessed due date is worse
/// than a refusal.
fn ledger_valid_time(body: &ClaimBody) -> Result<TimeRange> {
    let (Some(start), Some(end)) = (body.valid_from, body.valid_to) else {
        return Err(Error::InvalidClaimBody(
            "commitment claim missing valid-time bound",
        ));
    };
    Ok(TimeRange { start, end })
}

/// Orders one side of a ledger by due window, then by id so equal windows keep
/// a stable order. `learned_at` is deliberately absent: when the vault heard
/// about an obligation says nothing about when it comes due.
fn sort_due(entries: &mut [CommitmentLedgerEntry]) {
    entries.sort_by(|left, right| {
        left.valid_time
            .start
            .cmp(&right.valid_time.start)
            .then(left.valid_time.end.cmp(&right.valid_time.end))
            .then(left.commitment_id.cmp(&right.commitment_id))
    });
}

#[cfg(test)]
mod tests;
