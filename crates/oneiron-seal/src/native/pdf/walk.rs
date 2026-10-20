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

use crate::api::{Counter, note_current};

/// The object `object` names, with the id of its chain's last link: itself
/// and `from` when it is not a reference. `None` for a dangling or cyclic
/// chain; `from`, the id `object` was read at, counts as met. The links
/// taken are noted against `counter`.
fn follow<'d>(
    doc: &'d Document,
    from: Option<ObjectId>,
    mut object: &'d Object,
    counter: Counter,
) -> Option<(Option<ObjectId>, &'d Object)> {
    let mut last = from;
    let mut seen: BTreeSet<ObjectId> = from.into_iter().collect();
    let mut links = 0usize;
    let resolved = loop {
        let Object::Reference(id) = object else {
            break Some((last, object));
        };
        if !seen.insert(*id) {
            break None;
        }
        links += 1;
        last = Some(*id);
        match doc.objects.get(id) {
            Some(next) => object = next,
            None => break None,
        }
    };
    note_current(counter, links);
    resolved
}

/// [`follow`] for any reference the analysis reads: the terminal object
/// and the id of the chain's last link (`None` when `object` is not a
/// reference), as lopdf's `dereference` returns them.
pub(crate) fn chain<'d>(
    doc: &'d Document,
    object: &'d Object,
) -> Option<(Option<ObjectId>, &'d Object)> {
    follow(doc, None, object, Counter::ReferenceHops)
}

/// The terminal object `object` names, or itself.
pub(crate) fn resolve<'d>(doc: &'d Document, object: &'d Object) -> Option<&'d Object> {
    chain(doc, object).map(|(_, object)| object)
}

/// The terminal object a security-checked name slot (`/Type`, `/FT`, `/S`)
/// names. Its links count against their own row: a name hidden behind a
/// chain is still compared, however long the chain.
pub(crate) fn resolve_security_name<'d>(
    doc: &'d Document,
    object: &'d Object,
) -> Option<&'d Object> {
    follow(doc, None, object, Counter::SecurityNameHops).map(|(_, object)| object)
}

/// The terminal object of the chain starting at object `id`, as lopdf's
/// `get_object` reads it.
pub(crate) fn resolve_id(doc: &Document, id: ObjectId) -> Option<&Object> {
    let first = doc.objects.get(&id)?;
    follow(doc, Some(id), first, Counter::ReferenceHops).map(|(_, object)| object)
}

/// The dictionary object `id` names, as lopdf's `get_dictionary` reads it.
pub(crate) fn dictionary(doc: &Document, id: ObjectId) -> Option<&Dictionary> {
    resolve_id(doc, id)?.as_dict().ok()
}

/// The document catalog: the trailer's `/Root` reference, followed whole.
pub(crate) fn catalog(doc: &Document) -> Option<&Dictionary> {
    let root = doc.trailer.get(b"Root").ok()?.as_reference().ok()?;
    dictionary(doc, root)
}

/// The `/Kids` array of page-tree node `id`.
fn kids(doc: &Document, id: ObjectId) -> Option<&[Object]> {
    let node = dictionary(doc, id)?;
    let kids = resolve(doc, node.get(b"Kids").ok()?)?;
    kids.as_array().ok().map(Vec::as_slice)
}

/// The page objects of the document's page tree, in document order, as
/// lopdf's `get_pages` lists them: every `/Page` a `/Kids` entry names by
/// reference, however deep its `/Pages` node sits. A `/Pages` node met
/// again is walked once, so a cycle ends; a page named twice is listed
/// twice, as lopdf lists it.
pub(crate) fn pages(doc: &Document) -> Vec<ObjectId> {
    let mut out = Vec::new();
    let Some(root) = catalog(doc)
        .and_then(|catalog| catalog.get(b"Pages").ok())
        .and_then(|pages| pages.as_reference().ok())
    else {
        return out;
    };
    let mut walked = BTreeSet::from([root]);
    let mut open: Vec<std::slice::Iter<'_, Object>> = Vec::new();
    if let Some(top) = kids(doc, root) {
        open.push(top.iter());
    }
    while let Some(level) = open.last_mut() {
        let Some(kid) = level.next() else {
            open.pop();
            continue;
        };
        let Ok(id) = kid.as_reference() else {
            continue;
        };
        let Some(Ok(kind)) = dictionary(doc, id).map(Dictionary::get_type) else {
            continue;
        };
        match kind {
            b"Page" => out.push(id),
            b"Pages" if walked.insert(id) => {
                if let Some(next) = kids(doc, id) {
                    open.push(next.iter());
                }
            }
            _ => {}
        }
    }
    out
}
