//! DSS-revision coverage measurement: reference-chain collection and the
//! provable end offset of the effective `/DSS` revision.

use super::*;

/// Follow a reference chain exactly as the evaluation's resolver does,
/// recording every traversed object id (link and target alike) into a set
/// shared across all chains, so repetitions of one chain collapse to its
/// unique objects. A chain is followed whole however long (Rule 5): a link
/// met twice in this chain is a cycle, and a missing object a dangling
/// link; either leaves the terminal object's coverage unprovable (`None`)
/// and the caller fails closed. An id already in `ids` was reached by a
/// chain collected whole before, so the rest of this one is there too: the
/// walk stops at it, and N occurrences of one deep chain cost N steps, not
/// N times its length. `work` counts the steps of every chain, for the
/// `[limits]` DSS reference-work row.
pub(in crate::native::verify) fn collect_reference_chain(
    doc: &Document,
    id: lopdf::ObjectId,
    ids: &mut std::collections::BTreeSet<lopdf::ObjectId>,
    work: &mut usize,
    limits: &SealResourceLimits,
) -> Result<Option<()>, SealMemoryRefusal> {
    let mut chain = std::collections::BTreeSet::new();
    let mut current = id;
    loop {
        *work = work.saturating_add(1);
        if ids.contains(&current) {
            break;
        }
        if !pdf::admitted::btree_insert(limits, &mut chain, current)? {
            return Ok(None);
        }
        let Some(object) = doc.objects.get(&current) else {
            return Ok(None);
        };
        let Ok(next) = object.as_reference() else {
            break;
        };
        current = next;
    }
    for id in chain {
        pdf::admitted::btree_insert(limits, ids, id)?;
    }
    Ok(Some(()))
}

/// Byte offset the effective `/DSS` revision provably ends before: the
/// smallest xref-table offset beyond the newest DSS-related object (the
/// final catalog, the `/DSS` dictionary, and its `/Certs` `/OCSPs` `/CRLs`
/// array and stream objects), or the final `startxref` when no later object
/// exists. Objects of one revision precede that revision's xref, so a
/// DocTimeStamp whose ByteRange end reaches this offset covers every byte
/// of the revision the `/DSS` lives in; an earlier end validates evidence
/// no timestamp attests. `None` when coverage is unprovable (no `/DSS`,
/// compressed or missing xref entries, unparsable catalog): the
/// archival-time selection must then fall back to the verification clock so
/// stale evidence fails instead of laundering through an unrelated old
/// timestamp.
///
/// The measured id set must mirror the EVALUATION dereference paths exactly:
/// the shared resolver follows reference CHAINS whole, so every traversed
/// object is collected — a bare-reference link collected without its target
/// would let terminal evidence sit past the measured offsets, planted in a
/// revision no DocTimeStamp attests (probe_c regression). The evaluation
/// and this measurement resolve through the same uncapped walk, so neither
/// stops where the other goes on.
pub(in crate::native::verify) fn dss_revision_end(
    doc: &Document,
    bytes: &[u8],
    limits: &SealResourceLimits,
) -> Result<Option<u64>, SealMemoryRefusal> {
    let mut work = 0usize;
    let collected = dss_object_ids(doc, &mut work, limits);
    note_current(Counter::DssReferenceWork, work);
    let Some(ids) = collected? else {
        return Ok(None);
    };
    let mut newest = None;
    for (num, generation) in ids {
        match doc.reference_table.get(num) {
            Some(lopdf::xref::XrefEntry::Normal {
                offset,
                generation: g,
            }) if *g == generation => {
                let offset = u64::from(*offset);
                newest = Some(newest.map_or(offset, |n: u64| n.max(offset)));
            }
            _ => return Ok(None), // compressed or missing: coverage unprovable
        }
    }
    let Some(newest) = newest else {
        return Ok(None);
    };
    Ok(doc
        .reference_table
        .entries
        .values()
        .filter_map(|e| match e {
            lopdf::xref::XrefEntry::Normal { offset, .. } => Some(u64::from(*offset)),
            _ => None,
        })
        .filter(|o| *o > newest)
        .min()
        .or_else(|| pdf::last_startxref(bytes).ok()))
}

/// Every object id the effective `/DSS` reaches through the chains the
/// evaluation follows: the trailer's `/Root` and catalog, the `/DSS`
/// dictionary, and its `/Certs` `/OCSPs` `/CRLs` arrays and their entries.
/// `work` counts the reference steps taken, on a failed measurement too.
fn dss_object_ids(
    doc: &Document,
    work: &mut usize,
    limits: &SealResourceLimits,
) -> Result<Option<std::collections::BTreeSet<lopdf::ObjectId>>, SealMemoryRefusal> {
    let Some(catalog) = pdf::catalog(doc, limits)? else {
        return Ok(None);
    };
    let Ok(dss_obj) = catalog.get(b"DSS") else {
        return Ok(None);
    };
    let mut ids: std::collections::BTreeSet<lopdf::ObjectId> = std::collections::BTreeSet::new();
    if let Ok(root) = doc.trailer.get(b"Root").and_then(Object::as_reference) {
        if collect_reference_chain(doc, root, &mut ids, work, limits)?.is_none() {
            return Ok(None);
        }
    }
    if let Object::Reference(id) = dss_obj {
        if collect_reference_chain(doc, *id, &mut ids, work, limits)?.is_none() {
            return Ok(None);
        }
    }
    let Some(dss) = pdf::resolve(doc, dss_obj, limits)?.and_then(|o| o.as_dict().ok()) else {
        return Ok(None);
    };
    for key in [b"Certs".as_slice(), b"OCSPs".as_slice(), b"CRLs".as_slice()] {
        let Ok(arr_obj) = dss.get(key) else {
            continue;
        };
        if let Object::Reference(id) = arr_obj {
            if collect_reference_chain(doc, *id, &mut ids, work, limits)?.is_none() {
                return Ok(None);
            }
        }
        let Some(arr) = pdf::resolve(doc, arr_obj, limits)?.and_then(|o| o.as_array().ok()) else {
            continue;
        };
        for item in arr {
            if let Object::Reference(id) = item {
                if collect_reference_chain(doc, *id, &mut ids, work, limits)?.is_none() {
                    return Ok(None);
                }
            }
        }
    }
    Ok(Some(ids))
}
