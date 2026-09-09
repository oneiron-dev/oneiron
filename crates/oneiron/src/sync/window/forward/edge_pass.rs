//! Edge pass of forward rematerialization: materialize window edge rows into LMDB.

use super::super::bridge;
use super::super::egress::push_terminal_quarantine_marker;
use super::super::loro_support::{map_for_each_value_bytes, tombstone_map_contains_id};
use super::super::quarantine::{self, QuarantineContainer};
use super::{RematCtx, RematLedger};

use crate::batch::EdgeValueFields;
use crate::edge::decode_edge_value_for_kind;
use crate::error::{Error, Result};
use crate::store::Store;

/// Run the edge pass: iterate the window `edges` map, filter tombstoned
/// endpoints, byte-compare against LMDB, and write what differs.
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> Result<()> {
    let vault = ctx.vault;
    let window_key = ctx.window_key;
    let edges_map = &ctx.edges_map;
    let tombstones_map = &ctx.tombstones_map;
    let marked = &ledger.marked;
    let healed = &mut ledger.healed;
    let terminal_quarantines = &mut ledger.terminal_quarantines;
    let mut count = ledger.count;

    // Edges (endpoint + tombstone filtering, stored-value byte-compare).
    // ARCH-0023b step 5 byte-compares edges too ("write any that differ"):
    // an exists-skip would let a CRDT edge carrying confirmation_status =
    // retracted (value[24] == 3) lose to a stale local Active stamp, and the
    // PPR retracted gate would keep propagating withdrawn provenance.
    {
        enum EdgeRematOutcome {
            Written,
            Unchanged,
            Deferred,
            Quarantined,
        }

        let mut edge_error = None;
        map_for_each_value_bytes(edges_map, |key, buf| {
            if edge_error.is_some() {
                return;
            }
            // ONE-1157 (edge-pass parity, same gap as the entity pass):
            // non-Binary value where an edge value belongs — quarantined
            // like Observer B's non-Binary edge arm, never an invisible
            // skip.
            let Some(buf) = buf else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &Error::InvalidKey,
                    &[],
                ) {
                    edge_error = Some(err);
                } else {
                    push_terminal_quarantine_marker(
                        terminal_quarantines,
                        QuarantineContainer::Edges,
                        key,
                    );
                }
                return;
            };
            let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &Error::InvalidKey,
                    buf,
                ) {
                    edge_error = Some(err);
                }
                return;
            };

            // Decode BEFORE the tombstone/endpoint gates (mirrors Observer
            // B's ordering in bridge.rs): a malformed value is a remote
            // rejection regardless of endpoint state, and decode has no side
            // effects. Checking endpoints first would silently defer a
            // valid-key malformed edge whose endpoint is absent — no x: row.
            let decoded = match decode_edge_value_for_kind(kind, buf) {
                Ok(decoded) => decoded,
                Err(err) => {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Edges,
                        key,
                        &err,
                        buf,
                    ) {
                        edge_error = Some(q_err);
                    } else {
                        terminal_quarantines.push(src);
                    }
                    return;
                }
            };

            // Never re-add an edge whose endpoint is tombstoned in the CRDT.
            // ANY-value, entity-canonical presence — a non-binary tombstone
            // gates too, and a case-shifted hex alias still names the id.
            if tombstone_map_contains_id(tombstones_map, &src)
                || tombstone_map_contains_id(tombstones_map, &tgt)
            {
                return;
            }

            // The reserved-kind mandate, endpoint readiness, stored-byte
            // comparison, and paired write share ONE LMDB write txn. A
            // separate read check followed by `batch().commit()` would let
            // an intervening undo revoke the mandate before the edge write.
            let result = vault.with_write_txn(|wtxn| {
                if let Err(reserved) = crate::edge::validate_public_edge_kind(kind) {
                    let mandated_at = vault
                        .identity_topology_mandated_shell_edge_in_txn(&*wtxn, &src, kind, &tgt)?;
                    let door_echo = mandated_at.is_some_and(|at| {
                        decoded.created_at == at && kind.default_weight() == Some(decoded.weight)
                    });
                    if !door_echo {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &reserved,
                            buf,
                        )?;
                        return Ok(EdgeRematOutcome::Quarantined);
                    }
                }

                let src_exists = vault.store.entities.get(&*wtxn, src.as_bytes())?.is_some();
                let tgt_exists = vault.store.entities.get(&*wtxn, tgt.as_bytes())?.is_some();
                if !src_exists || !tgt_exists {
                    return Ok(EdgeRematOutcome::Deferred);
                }

                // ONE-1645 replay door for the FacetOf type table. The batch
                // arm this write lands on (`BatchOp::EdgeWithCreatedAt`) is
                // deliberately UNGATED — a hard abort there would wedge sync
                // permanently (H2) — so the table is enforced HERE, at the
                // remat chokepoint, as a quarantine-and-continue rejection.
                //
                // Without it a federation peer could replay an off-table
                // stamp (e.g. PERSON -> FACET) that no local public writer
                // can write, and it would reach LMDB — where the local query
                // door reads facet adjacency with no admitted-set filter of
                // its own. The federation selector no longer honors such a
                // source (`selector::facet_scope_by_source` mirrors this same
                // table on read), but the LMDB write is still an
                // authorization-boundary bypass via replay: this door is what
                // keeps the shape out of the retrieval truth at all.
                //
                // Ordered AFTER the endpoint-existence check on purpose: a
                // cross-window endpoint that has not arrived yet is a
                // DEFERRAL, not a rejection, and the type table reads
                // endpoint types from the entity rows this check just proved
                // present. Reversing the order would burn a legitimate
                // out-of-order replay as a permanent quarantine.
                //
                // The match is GUARDED (ONE-1124 fail-closed split): only a
                // remote-classifiable error may quarantine. The table also
                // surfaces LOCAL faults — `CorruptedIndex("entity header")`
                // on a stored row it cannot parse, and heed read errors on
                // the type lookups themselves — and those must ABORT the
                // drain. Quarantining one would be doubly wrong: it swallows
                // our own storage defect behind a continue, and the `x:` row
                // it writes is PERMANENT false evidence accusing the peer of
                // a forgery it never sent.
                match crate::batch::validate_facet_of_edge(&vault.store, &*wtxn, src, kind, tgt) {
                    Ok(()) => {}
                    Err(off_table) if quarantine::remote_rejection_reason(&off_table).is_some() => {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &off_table,
                            buf,
                        )?;
                        return Ok(EdgeRematOutcome::Quarantined);
                    }
                    Err(local) => return Err(local),
                }

                let out_key = Store::encode_edge_key(&src, kind, &tgt);
                let in_key = Store::encode_edge_key(&tgt, kind, &src);
                let out_matches = vault
                    .store
                    .edges_out
                    .get(&*wtxn, &out_key)?
                    .is_some_and(|value| value == buf);
                let in_matches = vault
                    .store
                    .edges_in
                    .get(&*wtxn, &in_key)?
                    .is_some_and(|value| value == buf);
                if out_matches && in_matches {
                    return Ok(EdgeRematOutcome::Unchanged);
                }

                vault
                    .batch_in()
                    .edge_with_value_fields(
                        &src,
                        kind,
                        &tgt,
                        EdgeValueFields::from_decoded(decoded),
                    )
                    .apply(wtxn)?;
                Ok(EdgeRematOutcome::Written)
            });
            match result {
                Ok(EdgeRematOutcome::Written) => {
                    count += 1;
                    // ONE-1147: a healing edge write discharges the SOURCE
                    // entity's needs-remat marker (Observer B's edge batch
                    // swallow site marks lost upserts by source id).
                    if marked.contains(&src.to_hex()) {
                        healed.push(src);
                    }
                }
                Ok(EdgeRematOutcome::Unchanged) => {}
                Ok(EdgeRematOutcome::Deferred) => {
                    // Deferral, not a rejection: cross-window endpoints
                    // arrive later; the edge stays in the CRDT and
                    // re-materializes when its endpoints do.
                    tracing::debug!(
                        edge = %key,
                        "forward remat: edge deferred — endpoint absent"
                    );
                }
                Ok(EdgeRematOutcome::Quarantined) => {
                    // The reserved-kind rejection and its durable evidence
                    // committed in the edge txn above. Keep iterating: one
                    // forged row must not starve the other N-1 edge heals.
                    terminal_quarantines.push(src);
                }
                Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Edges,
                        key,
                        &err,
                        buf,
                    ) {
                        edge_error = Some(q_err);
                    } else {
                        terminal_quarantines.push(src);
                    }
                }
                Err(err) => {
                    // LOCAL failure — fail closed.
                    edge_error = Some(err);
                }
            }
        });
        if let Some(err) = edge_error {
            return Err(err);
        }
    }
    ledger.count = count;
    Ok(())
}
