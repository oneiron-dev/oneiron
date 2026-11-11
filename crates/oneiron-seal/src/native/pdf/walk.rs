//! Reference chains and the page tree, followed whole (Rule 5).
//!
//! lopdf's own `dereference` gives up after 128 links and its page iterator
//! skips a `/Pages` node more than 256 levels down. Here a chain runs through
//! the raw object map to its terminal object however long it is: a link met
//! twice in one chain is a cycle and a missing object a dangling link, both
//! malformed, never "absent". The links each chain took go to the running
//! analysis's counts for the `[limits]` rows.

use std::collections::BTreeSet;

use lopdf::{Dictionary, Document, Object, ObjectId};

use super::admitted;
use crate::api::{Counter, SealResourceLimits, note_current};
use crate::memory::{Held, SealMemoryRefusal};

/// The object `object` names, with the id of its chain's last link: itself
/// and `from` when it is not a reference. `None` for a dangling or cyclic
/// chain; `from`, the id `object` was read at, counts as met. The links
/// taken are noted against `counter`. The per-chain seen set is admitted
/// before growth and drops before its charged bytes return to the ledger.
fn follow<'d>(
    doc: &'d Document,
    from: Option<ObjectId>,
    mut object: &'d Object,
    counter: Counter,
    limits: &SealResourceLimits,
) -> Result<Option<(Option<ObjectId>, &'d Object)>, SealMemoryRefusal> {
    let ledger = limits.memory.ledger()?;
    let mut last = from;
    let mut seen = BTreeSet::new();
    let mut links = 0usize;
    let resolved = (|| {
        if let Some(id) = from {
            admitted::btree_insert(limits, &mut seen, id)?;
        }
        let resolved = loop {
            let Object::Reference(id) = object else {
                break Some((last, object));
            };
            if !admitted::btree_insert(limits, &mut seen, *id)? {
                break None;
            }
            links += 1;
            last = Some(*id);
            match doc.objects.get(id) {
                Some(next) => object = next,
                None => break None,
            }
        };
        Ok(resolved)
    })();
    note_current(counter, links);
    let seen_n = seen.len();
    drop(seen);
    let seen_bytes = admitted::btree_charged::<ObjectId, ()>(seen_n);
    ledger.release_admitted(u64::try_from(seen_bytes).unwrap_or(u64::MAX));
    resolved
}

/// [`follow`] for any reference the analysis reads: the terminal object
/// and the id of the chain's last link (`None` when `object` is not a
/// reference), as lopdf's `dereference` returns them.
pub(crate) fn chain<'d>(
    doc: &'d Document,
    object: &'d Object,
    limits: &SealResourceLimits,
) -> Result<Option<(Option<ObjectId>, &'d Object)>, SealMemoryRefusal> {
    follow(doc, None, object, Counter::ReferenceHops, limits)
}

/// The terminal object `object` names, or itself.
pub(crate) fn resolve<'d>(
    doc: &'d Document,
    object: &'d Object,
    limits: &SealResourceLimits,
) -> Result<Option<&'d Object>, SealMemoryRefusal> {
    Ok(chain(doc, object, limits)?.map(|(_, object)| object))
}

/// The terminal object a security-checked name slot (`/Type`, `/FT`, `/S`)
/// names. Its links count against their own row: a name hidden behind a
/// chain is still compared, however long the chain.
pub(crate) fn resolve_security_name<'d>(
    doc: &'d Document,
    object: &'d Object,
    limits: &SealResourceLimits,
) -> Result<Option<&'d Object>, SealMemoryRefusal> {
    Ok(follow(doc, None, object, Counter::SecurityNameHops, limits)?.map(|(_, object)| object))
}

/// The terminal object of the chain starting at object `id`, as lopdf's
/// `get_object` reads it.
pub(crate) fn resolve_id<'d>(
    doc: &'d Document,
    id: ObjectId,
    limits: &SealResourceLimits,
) -> Result<Option<&'d Object>, SealMemoryRefusal> {
    let Some(first) = doc.objects.get(&id) else {
        return Ok(None);
    };
    Ok(follow(doc, Some(id), first, Counter::ReferenceHops, limits)?.map(|(_, object)| object))
}

/// The dictionary object `id` names, as lopdf's `get_dictionary` reads it.
pub(crate) fn dictionary<'d>(
    doc: &'d Document,
    id: ObjectId,
    limits: &SealResourceLimits,
) -> Result<Option<&'d Dictionary>, SealMemoryRefusal> {
    Ok(resolve_id(doc, id, limits)?.and_then(|object| object.as_dict().ok()))
}

/// The document catalog: the trailer's `/Root` reference, followed whole.
pub(crate) fn catalog<'d>(
    doc: &'d Document,
    limits: &SealResourceLimits,
) -> Result<Option<&'d Dictionary>, SealMemoryRefusal> {
    let Some(root) = doc
        .trailer
        .get(b"Root")
        .ok()
        .and_then(|root| root.as_reference().ok())
    else {
        return Ok(None);
    };
    dictionary(doc, root, limits)
}

/// The `/Kids` array of page-tree node `id`.
fn kids<'d>(
    doc: &'d Document,
    id: ObjectId,
    limits: &SealResourceLimits,
) -> Result<Option<&'d [Object]>, SealMemoryRefusal> {
    let Some(node) = dictionary(doc, id, limits)? else {
        return Ok(None);
    };
    let Ok(kids) = node.get(b"Kids") else {
        return Ok(None);
    };
    Ok(resolve(doc, kids, limits)?
        .and_then(|kids| kids.as_array().ok())
        .map(Vec::as_slice))
}

/// Net bytes one `open`-level push charged (FIX 14217): the shared growth
/// formula for the stack's element type. A slice iterator's layout does not
/// depend on its lifetime, so `'static` names the type exactly.
fn open_charge(len: usize, capacity: usize) -> usize {
    admitted::growth_charge::<std::slice::Iter<'static, Object>>(len, capacity, 1)
}

/// The page objects of the document's page tree, in document order, as
/// lopdf's `get_pages` lists them: every `/Page` a `/Kids` entry names by
/// reference, however deep its `/Pages` node sits. A `/Pages` node met
/// again is walked once, so a cycle ends; a page named twice is listed
/// twice, as lopdf lists it. The output, the open levels, and the walked
/// set grow under the operation's ledger first (FIX 14203); a refusal ends
/// the walk as itself, never as a shorter page list. The output stays held
/// on the ledger until the caller drops it; the open levels and walked set
/// return their bytes on the success path (FIX 14217).
pub(crate) fn pages(
    doc: &Document,
    limits: &SealResourceLimits,
) -> Result<Held<Vec<ObjectId>>, SealMemoryRefusal> {
    let mut out = Vec::new();
    let mut out_charged = 0usize;
    let mut open_charged = 0usize;
    let Some(root) = catalog(doc, limits)?
        .and_then(|catalog| catalog.get(b"Pages").ok())
        .and_then(|pages| pages.as_reference().ok())
    else {
        let ledger = limits.memory.ledger()?;
        return Ok(Held::new(Vec::new(), ledger.adopt_charged(0)));
    };
    let mut walked = BTreeSet::new();
    admitted::btree_insert(limits, &mut walked, root)?;
    let mut open: Vec<std::slice::Iter<'_, Object>> = Vec::new();
    if let Some(top) = kids(doc, root, limits)? {
        let (len, capacity) = (open.len(), open.capacity());
        admitted::push(limits, &mut open, top.iter())?;
        open_charged = open_charged.saturating_add(open_charge(len, capacity));
    }
    while let Some(level) = open.last_mut() {
        let Some(kid) = level.next() else {
            open.pop();
            continue;
        };
        let Ok(id) = kid.as_reference() else {
            continue;
        };
        let Some(Ok(kind)) = dictionary(doc, id, limits)?.map(Dictionary::get_type) else {
            continue;
        };
        match kind {
            b"Page" => {
                let (len, capacity) = (out.len(), out.capacity());
                admitted::push(limits, &mut out, id)?;
                let charge = admitted::growth_charge::<ObjectId>(len, capacity, 1);
                out_charged = out_charged.saturating_add(charge);
            }
            b"Pages" => {
                if admitted::btree_insert(limits, &mut walked, id)? {
                    if let Some(next) = kids(doc, id, limits)? {
                        let (len, capacity) = (open.len(), open.capacity());
                        admitted::push(limits, &mut open, next.iter())?;
                        open_charged = open_charged.saturating_add(open_charge(len, capacity));
                    }
                }
            }
            _ => {}
        }
    }
    let ledger = limits.memory.ledger()?;
    let walked_n = walked.len();
    drop(open);
    drop(walked);
    let walked_bytes = admitted::btree_charged::<ObjectId, ()>(walked_n);
    ledger.release_admitted(u64::try_from(open_charged).unwrap_or(u64::MAX));
    ledger.release_admitted(u64::try_from(walked_bytes).unwrap_or(u64::MAX));
    Ok(Held::new(out, ledger.adopt_charged(out_charged)))
}
