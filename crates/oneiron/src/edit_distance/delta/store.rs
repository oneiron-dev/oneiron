//! Delta side-ledger writes, receipt attachment, and the identity-topology projection pass.

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::receipt::{
    FIELD_AMENDMENT_DELTA, FIELD_AMENDMENT_DELTA_UNCAPTURED, MAX_RECEIPT_QUERY_SCAN, ReceiptKind,
    ReceiptQuery, ReceiptRecord, proposal_outcome_amended_body,
};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::lanes::{DeltaCaptureContext, capture_delta_best};
use super::schema::AmendmentDelta;

/// Write-once Δ side-ledger row for one receipt, keyed by receipt id — the
/// same join key the reader uses, so writer and reader cannot drift apart.
const AMENDMENT_DELTA: SideTable<String, DeltaRow, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_DELTA);

/// Row value standing for "capture was ATTEMPTED here and failed". A captured
/// Δ row is canonical JSON, which always opens `{`, so a bare token can never
/// be read as one.
///
/// The row is what makes the failure honest: without it, a receipt whose
/// capture failed is byte-for-byte indistinguishable from one the projection
/// pass never visited.
const AMENDMENT_DELTA_UNCAPTURED_ROW: &[u8] = b"uncaptured";

/// The Δ side-ledger's row shape: a captured measurement, or the marker that
/// capture was attempted and failed.
pub(super) enum DeltaRow {
    Captured(AmendmentDelta),
    Uncaptured,
}

impl RawValue for DeltaRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        match self {
            Self::Captured(delta) => Ok(delta.encode()?),
            Self::Uncaptured => Ok(AMENDMENT_DELTA_UNCAPTURED_ROW.to_vec()),
        }
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes == AMENDMENT_DELTA_UNCAPTURED_ROW {
            return Ok(Self::Uncaptured);
        }
        Ok(Self::Captured(AmendmentDelta::decode(bytes)?))
    }
}

/// The outcome token a Δ-carrying receipt reports. Both amendment doors
/// (identity-topology resolution, ONE-1747; the inbox approve-with-edit door
/// below) stamp it, which is what makes ONE attach pass serve both.
pub(crate) const OUTCOME_APPROVED_AMENDED: &str = "approved_amended";

/// `trigger_ref` prefix a proposal-outcome receipt carries for its proposal.
pub(super) const PROPOSAL_TRIGGER_PREFIX: &str = "event:";

// ---------------------------------------------------------------------------
// Δ side-ledger + receipt attachment
// ---------------------------------------------------------------------------

/// Records `delta` against the receipt it describes, returning whether a row
/// was written.
///
/// **First writer wins.** A Δ is a measurement of a window that is already
/// closed, so a later pass re-measuring it (under a newer `engine_ver`, say)
/// has nothing new to say about what the decider did. Overwriting would make
/// a receipt's Δ drift under a reader who quoted it.
pub(crate) fn put_amendment_delta_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &str,
    delta: &AmendmentDelta,
) -> Result<bool> {
    put_amendment_row_in_txn(vault, wtxn, receipt_id, &DeltaRow::Captured(delta.clone()))
}

/// The write-once side-ledger row itself — a Δ payload or
/// [`DeltaRow::Uncaptured`]. Both outcomes are measurements of the same
/// closed window, so both take the same first-writer-wins law.
pub(super) fn put_amendment_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &str,
    row: &DeltaRow,
) -> Result<bool> {
    let key = receipt_id.to_owned();
    if AMENDMENT_DELTA.contains(&vault.store, &*wtxn, &key)? {
        return Ok(false);
    }
    AMENDMENT_DELTA.put(&vault.store, wtxn, &key, row)?;
    Ok(true)
}

/// The Δ recorded for `receipt_id`, if one was captured.
///
/// `None` covers both "never measured" and "measured and failed" — this
/// accessor answers for the Δ, and there is none either way. The RECEIPT is
/// where the two part company: attachment projects
/// `FIELD_AMENDMENT_DELTA_UNCAPTURED` for the second.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) on an undecodable row.
pub fn amendment_delta(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentDelta>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(match amendment_delta_in_txn(vault, &rtxn, receipt_id)? {
        Some(DeltaRow::Captured(delta)) => Some(delta),
        Some(DeltaRow::Uncaptured) | None => None,
    })
}

fn amendment_delta_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<Option<DeltaRow>> {
    AMENDMENT_DELTA.get(&vault.store, rtxn, &receipt_id.to_owned())
}

/// Whether this engine recorded an AMENDMENT against `receipt_id` — the
/// durable mark that a decider approved-and-changed, on the caller's snapshot.
///
/// Both row shapes answer `true`: a measured Δ and an
/// [`FIELD_AMENDMENT_DELTA_UNCAPTURED`] marker differ on whether the
/// measurement succeeded, not on whether the amendment happened. Every writer
/// of either row is gated on an `approved_amended` outcome
/// ([`project_identity_amendment_deltas`], `inbox`'s amend-accept), so the
/// presence of a row is the engine's own record that the outcome was
/// adjudicated — which is why [`record_amendment_evidence`] refuses a receipt
/// without one, and why a projection over amendments can gate on it rather
/// than re-deriving adjudication from receipt fields.
///
/// [`record_amendment_evidence`]: super::attribution::record_amendment_evidence
///
/// # Errors
///
/// Storage errors.
pub(in crate::edit_distance) fn amendment_recorded_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<bool> {
    AMENDMENT_DELTA.contains(&vault.store, rtxn, &receipt_id.to_owned())
}

/// Folds recorded Δs into the reserved `amendment_delta` slot of every
/// amended receipt in `records`, and a failed capture into its own
/// [`FIELD_AMENDMENT_DELTA_UNCAPTURED`] marker.
///
/// Two fields, because the two facts are different: a Δ says how much the
/// decider changed, the marker says the engine looked and could not tell. A
/// receipt carrying NEITHER has simply not been projected yet — which is a
/// third fact, and the reason the marker is written at all.
///
/// The `approved_amended` filter is the point: an unamended outcome has no Δ
/// by definition, so the common query pays no lookups at all.
pub(crate) fn attach_amendment_deltas(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    records: &mut [ReceiptRecord],
) -> Result<()> {
    for record in records
        .iter_mut()
        .filter(|record| record.outcome == OUTCOME_APPROVED_AMENDED)
    {
        let Some(row) = amendment_delta_in_txn(vault, rtxn, &record.receipt_id)? else {
            continue;
        };
        let (field, value) = match row {
            DeltaRow::Uncaptured => (FIELD_AMENDMENT_DELTA_UNCAPTURED, "true".to_owned()),
            DeltaRow::Captured(delta) => {
                (FIELD_AMENDMENT_DELTA, bytes_to_hex_lower(&delta.encode()?))
            }
        };
        record.fields.insert(field.to_owned(), value);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity-topology projection pass
// ---------------------------------------------------------------------------

/// Measures and records the Δ for every identity-topology amendment that has
/// none yet, returning how many rows this pass wrote.
///
/// Post-hoc BY DESIGN. The resolve door lives in the identity-topology spine
/// (ONE-1747) and already emits everything a Δ needs: the proposal it ruled
/// on (`trigger_ref`) and the amended body verbatim (`amended_body`). Reading
/// those two back beats reaching into another module's write path, and it is
/// what makes ONE-1747's two-slot contract hold — the producer artifact stays
/// byte-identical, the RESERVED slot is what this fills.
///
/// A receipt with no measurable PAIR — nothing amended, no resolvable
/// proposal — is SKIPPED, not raised: it stays eligible for a later pass, and
/// one unreadable proposal must not deny every other amendment its telemetry.
/// A receipt whose pair EXISTS and whose measurement fails is recorded as
/// `ProjectedDelta::Uncaptured` instead, because "capture failed" and "never
/// ran" are different facts a reader is entitled to tell apart. A Δ written
/// for a resolution the fold later suppresses is inert — attachment only
/// visits receipts that projected.
///
/// # Errors
///
/// Storage errors.
pub fn project_identity_amendment_deltas(vault: &Vault) -> Result<usize> {
    let mut query = ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN);
    query.kinds.insert(ReceiptKind::ProposalOutcome);
    query.outcome = Some(OUTCOME_APPROVED_AMENDED.to_owned());

    let mut pending: Vec<(String, ProjectedDelta)> = Vec::new();
    for receipt in vault.receipts(query)? {
        // Either marker means this receipt has already been measured. The
        // uncaptured one is what stops a failed capture from being retried by
        // every later pass: its cause is the stored bytes, which do not heal.
        if receipt.fields.contains_key(FIELD_AMENDMENT_DELTA)
            || receipt
                .fields
                .contains_key(FIELD_AMENDMENT_DELTA_UNCAPTURED)
        {
            continue;
        }
        if let Some(projected) = identity_amendment_delta(vault, &receipt)? {
            pending.push((receipt.receipt_id, projected));
        }
    }
    if pending.is_empty() {
        return Ok(0);
    }

    vault.with_write_txn(|wtxn| {
        let mut written = 0;
        for (receipt_id, projected) in &pending {
            let wrote = match projected {
                ProjectedDelta::Captured(delta) => {
                    put_amendment_delta_in_txn(vault, wtxn, receipt_id, delta)?
                }
                ProjectedDelta::Uncaptured => {
                    put_amendment_row_in_txn(vault, wtxn, receipt_id, &DeltaRow::Uncaptured)?
                }
            };
            if wrote {
                written += 1;
            }
        }
        Ok(written)
    })
}

/// What the projection measured for a receipt whose amendment window has both
/// ends in hand.
pub(super) enum ProjectedDelta {
    /// The Δ between the proposal and the body the decider approved.
    Captured(AmendmentDelta),
    /// The measurement failed. Recorded rather than dropped: a receipt saying
    /// its Δ is missing is worth more than one silently without, and the
    /// projection pass is resumable only because a visited row leaves a trace.
    Uncaptured,
}

/// The Δ between a resolved proposal's proposed op and the body the decider
/// approved, or `None` when this receipt does not carry a measurable pair.
pub(super) fn identity_amendment_delta(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<Option<ProjectedDelta>> {
    let Some(amended) = proposal_outcome_amended_body(receipt) else {
        return Ok(None);
    };
    let Some(proposal_hex) = receipt
        .trigger_ref
        .as_deref()
        .and_then(|trigger| trigger.strip_prefix(PROPOSAL_TRIGGER_PREFIX))
    else {
        return Ok(None);
    };
    let Ok(proposal_id) = EntityId::from_hex(proposal_hex) else {
        return Ok(None);
    };

    let rtxn = vault.store.env.read_txn()?;
    let Some(record) = vault.identity_topology_event_in_txn(&rtxn, &proposal_id)? else {
        return Ok(None);
    };
    drop(rtxn);

    let crate::identity_topology::IdentityTopologyAction::Apply(proposed_op) =
        record.action.to_fold_action()
    else {
        return Ok(None);
    };
    // Past this point BOTH ends of the window exist, so every remaining exit
    // is a measurement that failed, not a pair that was never there.
    //
    // The proposed side is re-encoded through the SAME door the amended body
    // rode (`encode_identity_op_amendment`), so the two trees are comparable
    // shapes rather than an event record against an op body.
    let Ok(proposed) = crate::identity_topology::encode_identity_op_amendment(&proposed_op) else {
        return Ok(Some(ProjectedDelta::Uncaptured));
    };
    Ok(Some(
        match capture_delta_best(&DeltaCaptureContext::from_bodies(&proposed, &amended)) {
            Ok(delta) => ProjectedDelta::Captured(delta),
            Err(_) => ProjectedDelta::Uncaptured,
        },
    ))
}
