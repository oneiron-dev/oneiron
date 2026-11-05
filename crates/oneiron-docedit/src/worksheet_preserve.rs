//! FIX9820 PART: restore wholly-missing worksheet root foreign groups and SML ext records.
//! Copies missing direct foreign root children and missing SML `extLst`/`ext` (by unqualified
//! `uri`) from before into after via insertions only. Ambiguous cases warn and skip; root attrs,
//! nested unknowns and partial groups stay open.
use crate::opc_package::OpcPackage;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::collections::{BTreeMap, BTreeSet};
const SML_NS: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
pub struct Preservation {
    pub changed: bool,
    pub warnings: Vec<String>,
}
/// Restore wholly-missing worksheet root extensions from `before` into `after` (insertions only).
/// Touches only existing after worksheet parts via `upsert`. Caller runs only when no edit was structural.
pub fn preserve_missing_root_extensions(
    before: &OpcPackage,
    after: &mut OpcPackage,
) -> Preservation {
    let mut warnings = Vec::new();
    let mut changed = false;
    let names: Vec<String> = after
        .names()
        .filter(|n| is_worksheet_part(n))
        .map(|s| s.to_owned())
        .collect();
    for name in names {
        let (Some(b), Some(a)) = (before.part(&name), after.part(&name)) else {
            continue;
        };
        if b == a {
            continue;
        }
        let (next, mut w) = preserve_one(&name, b, a);
        warnings.append(&mut w);
        if let Some(next) = next {
            after.upsert(name, next);
            changed = true;
        }
    }
    Preservation { changed, warnings }
}
fn is_worksheet_part(name: &str) -> bool {
    name.starts_with("xl/worksheets/") && name.ends_with(".xml") && !name.contains("/_rels/")
}
struct Child {
    ns: Option<String>,
    local: String,
    start: usize,
    end: usize,
    own: BTreeSet<String>,
}
struct ExtChild {
    ns: Option<String>,
    local: String,
    start: usize,
    end: usize,
    own: BTreeSet<String>,
    uri: Option<String>,
}
struct ExtLst {
    start: usize,
    end: usize,
    is_empty: bool,
    qualified: String,
    xmlns: BTreeMap<String, String>,
    end_tag_start: Option<usize>,
    exts: Vec<ExtChild>,
}
struct Parsed {
    root_qualified: String,
    root_is_empty: bool,
    root_end: usize,
    root_end_tag_start: Option<usize>,
    root_xmlns: BTreeMap<String, String>,
    children: Vec<Child>,
    extlsts: Vec<ExtLst>,
}
struct Pending {
    ns: Option<String>,
    local: String,
    start: usize,
    own: BTreeSet<String>,
    qualified: String,
    xmlns: BTreeMap<String, String>,
}
struct PendingExt {
    ns: Option<String>,
    local: String,
    start: usize,
    own: BTreeSet<String>,
    uri: Option<String>,
}
fn is_sml_extlst(ns: &Option<String>, local: &str) -> bool {
    ns.as_deref() == Some(SML_NS) && local == "extLst"
}
fn is_sml_ext(ns: &Option<String>, local: &str) -> bool {
    ns.as_deref() == Some(SML_NS) && local == "ext"
}
fn preserve_one(part: &str, before: &[u8], after: &[u8]) -> (Option<Vec<u8>>, Vec<String>) {
    let mut warnings = Vec::new();
    let pb = match parse_worksheet(before) {
        Ok(p) => p,
        Err(e) => return (None, vec![format!("{part}: before {e}")]),
    };
    let pa = match parse_worksheet(after) {
        Ok(p) => p,
        Err(e) => return (None, vec![format!("{part}: after {e}")]),
    };
    let after_set: BTreeSet<(Option<String>, String)> = pa
        .children
        .iter()
        .map(|c| (c.ns.clone(), c.local.clone()))
        .collect();
    let mut bc: BTreeMap<(Option<String>, String), usize> = BTreeMap::new();
    for c in &pb.children {
        if c.ns.as_deref() != Some(SML_NS) {
            *bc.entry((c.ns.clone(), c.local.clone())).or_default() += 1;
        }
    }
    let mut ac: BTreeMap<(Option<String>, String), usize> = BTreeMap::new();
    for c in &pa.children {
        if c.ns.as_deref() != Some(SML_NS) {
            *ac.entry((c.ns.clone(), c.local.clone())).or_default() += 1;
        }
    }
    for ((ns, local), n) in &bc {
        if after_set.contains(&(ns.clone(), local.clone())) {
            let m = ac.get(&(ns.clone(), local.clone())).copied().unwrap_or(0);
            if *n > m {
                warnings.push(format!("{part}: foreign {}#{} partially present (before {n}, after {m}); left unchanged (PART)", ns.as_deref().unwrap_or("(no-ns)"), local));
            }
        }
    }
    let missing_foreign: Vec<&Child> = pb
        .children
        .iter()
        .filter(|c| {
            c.ns.as_deref() != Some(SML_NS) && !after_set.contains(&(c.ns.clone(), c.local.clone()))
        })
        .collect();
    let (bn, an) = (pb.extlsts.len(), pa.extlsts.len());
    let mut whole = false;
    let mut missing_exts: Vec<&ExtChild> = Vec::new();
    if bn > 1 || an > 1 {
        warnings.push(format!("{part}: ambiguous multiple extLst (before {bn}, after {an}); extLst left unchanged (PART)"));
    } else if bn == 1 && an == 0 {
        let (miss, counts) = sml_uri_stats(&pb.extlsts[0].exts);
        if miss > 0 {
            warnings.push(format!(
                "{part}: before extLst has {miss} ext with missing uri; whole extLst copied"
            ));
        }
        let d = duplicate_uris(&counts);
        if !d.is_empty() {
            warnings.push(format!(
                "{part}: before extLst duplicate uri(s) {}; whole extLst copied",
                d.join(", ")
            ));
        }
        whole = true;
    } else if bn == 1 && an == 1 {
        let (bm, bcounts) = sml_uri_stats(&pb.extlsts[0].exts);
        let (am, acounts) = sml_uri_stats(&pa.extlsts[0].exts);
        if bm > 0 {
            warnings.push(format!(
                "{part}: before extLst has {bm} ext with missing uri; skipped"
            ));
        }
        let bd = duplicate_uris(&bcounts);
        if !bd.is_empty() {
            warnings.push(format!(
                "{part}: before extLst duplicate uri(s) {}; those uris skipped",
                bd.join(", ")
            ));
        }
        if am > 0 {
            warnings.push(format!(
                "{part}: after extLst has {am} ext with missing uri; preserved as-is (PART)"
            ));
        }
        let ad = duplicate_uris(&acounts);
        if !ad.is_empty() {
            warnings.push(format!(
                "{part}: after extLst duplicate uri(s) {}; preserved as-is",
                ad.join(", ")
            ));
        }
        let aset: BTreeSet<String> = acounts.keys().cloned().collect();
        for e in &pb.extlsts[0].exts {
            if !is_sml_ext(&e.ns, &e.local) {
                continue;
            }
            let Some(uri) = e.uri.as_ref() else { continue };
            if bcounts.get(uri).copied().unwrap_or(0) == 1 && !aset.contains(uri) {
                missing_exts.push(e);
            }
        }
    } else if bn == 0 && an == 1 {
        let (am, acounts) = sml_uri_stats(&pa.extlsts[0].exts);
        if am > 0 {
            warnings.push(format!(
                "{part}: after extLst has {am} ext with missing uri; preserved as-is (PART)"
            ));
        }
        let ad = duplicate_uris(&acounts);
        if !ad.is_empty() {
            warnings.push(format!(
                "{part}: after extLst duplicate uri(s) {}; preserved as-is",
                ad.join(", ")
            ));
        }
    }
    if missing_foreign.is_empty() && !whole && missing_exts.is_empty() {
        return (None, warnings);
    }
    let mut root_insert = Vec::new();
    for c in missing_foreign {
        root_insert.extend_from_slice(&inject_xmlns(
            &before[c.start..c.end],
            &missing_bindings(&pb.root_xmlns, &c.own),
        ));
    }
    if whole {
        let e = &pb.extlsts[0];
        let own: BTreeSet<String> = e.xmlns.keys().cloned().collect();
        root_insert.extend_from_slice(&inject_xmlns(
            &before[e.start..e.end],
            &missing_bindings(&pb.root_xmlns, &own),
        ));
    }
    let mut ext_insert = Vec::new();
    if !missing_exts.is_empty() {
        let mut inherited = pb.root_xmlns.clone();
        for (k, v) in &pb.extlsts[0].xmlns {
            inherited.insert(k.clone(), v.clone());
        }
        for e in missing_exts {
            ext_insert.extend_from_slice(&inject_xmlns(
                &before[e.start..e.end],
                &missing_bindings(&inherited, &e.own),
            ));
        }
    }
    match assemble(part, after, &pa, &root_insert, &ext_insert) {
        Ok(out) => (Some(out), warnings),
        Err(m) => {
            warnings.push(m);
            (None, warnings)
        }
    }
}
fn sml_uri_stats(exts: &[ExtChild]) -> (usize, BTreeMap<String, usize>) {
    let mut miss = 0;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in exts {
        if !is_sml_ext(&e.ns, &e.local) {
            continue;
        }
        match &e.uri {
            None => miss += 1,
            Some(u) => *counts.entry(u.clone()).or_default() += 1,
        }
    }
    (miss, counts)
}
fn duplicate_uris(counts: &BTreeMap<String, usize>) -> Vec<String> {
    counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(u, _)| u.clone())
        .collect()
}
fn missing_bindings(
    inherited: &BTreeMap<String, String>,
    own: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    inherited
        .iter()
        .filter(|(p, _)| !own.contains(*p))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
fn assemble(
    part: &str,
    after: &[u8],
    pa: &Parsed,
    root_insert: &[u8],
    ext_insert: &[u8],
) -> Result<Vec<u8>, String> {
    let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    if pa.root_is_empty {
        if !ext_insert.is_empty() {
            return Err(format!(
                "{part}: unexpected ext insertion into empty root; skipped (PART)"
            ));
        }
        if pa.root_end < 2 || &after[pa.root_end - 2..pa.root_end] != b"/>" {
            return Err(format!(
                "{part}: after empty root tag malformed; left unchanged (PART)"
            ));
        }
        let mut rep = vec![b'>'];
        rep.extend_from_slice(root_insert);
        rep.extend_from_slice(b"</");
        rep.extend_from_slice(pa.root_qualified.as_bytes());
        rep.push(b'>');
        edits.push((pa.root_end - 2, pa.root_end, rep));
    } else {
        let Some(rend) = pa.root_end_tag_start else {
            return Err(format!(
                "{part}: after root end missing; left unchanged (PART)"
            ));
        };
        if pa.extlsts.is_empty() {
            if !ext_insert.is_empty() {
                return Err(format!(
                    "{part}: unexpected ext insertion without after extLst; skipped (PART)"
                ));
            }
            edits.push((rend, rend, root_insert.to_vec()));
        } else if pa.extlsts.len() > 1 {
            if !ext_insert.is_empty() {
                return Err(format!(
                    "{part}: unexpected ext insertion with multiple after extLst; skipped (PART)"
                ));
            }
            edits.push((
                pa.extlsts[0].start,
                pa.extlsts[0].start,
                root_insert.to_vec(),
            ));
        } else {
            let h = &pa.extlsts[0];
            if !root_insert.is_empty() {
                edits.push((h.start, h.start, root_insert.to_vec()));
            }
            if !ext_insert.is_empty() {
                if h.is_empty {
                    if h.end < 2 || &after[h.end - 2..h.end] != b"/>" {
                        return Err(format!(
                            "{part}: after empty extLst tag malformed; left unchanged (PART)"
                        ));
                    }
                    let mut rep = vec![b'>'];
                    rep.extend_from_slice(ext_insert);
                    rep.extend_from_slice(b"</");
                    rep.extend_from_slice(h.qualified.as_bytes());
                    rep.push(b'>');
                    edits.push((h.end - 2, h.end, rep));
                } else {
                    let Some(eend) = h.end_tag_start else {
                        return Err(format!(
                            "{part}: after extLst end missing; left unchanged (PART)"
                        ));
                    };
                    edits.push((eend, eend, ext_insert.to_vec()));
                }
            }
        }
    }
    edits.sort_by_key(|(s, _, _)| *s);
    let mut out = Vec::with_capacity(after.len() + root_insert.len() + ext_insert.len() + 64);
    let mut cursor = 0;
    for (s, e, rep) in edits {
        if s > e || e > after.len() || s < cursor {
            return Err(format!(
                "{part}: after offsets invalid; left unchanged (PART)"
            ));
        }
        out.extend_from_slice(&after[cursor..s]);
        out.extend_from_slice(&rep);
        cursor = e;
    }
    out.extend_from_slice(&after[cursor..]);
    Ok(out)
}
fn parse_worksheet(xml: &[u8]) -> Result<Parsed, &'static str> {
    let text = std::str::from_utf8(xml).map_err(|_| "XML is not UTF-8")?;
    let mut r = NsReader::from_str(text);
    let mut open: Vec<String> = Vec::new();
    let mut seen = false;
    let mut q = String::new();
    let mut empty = false;
    let mut rend = 0;
    let mut rend_start = None;
    let mut rxmlns: BTreeMap<String, String> = BTreeMap::new();
    let mut rns = None;
    let mut rlocal = String::new();
    let mut children: Vec<Child> = Vec::new();
    let mut extlsts: Vec<ExtLst> = Vec::new();
    let mut pend: Option<Pending> = None;
    let mut pexts: Vec<ExtChild> = Vec::new();
    let mut pext: Option<PendingExt> = None;
    let in_extlst =
        |p: &Option<Pending>| p.as_ref().is_some_and(|x| is_sml_extlst(&x.ns, &x.local));
    loop {
        let bpos = r.buffer_position() as usize;
        let ev = r.read_event().map_err(|_| "malformed XML")?;
        let apos = r.buffer_position() as usize;
        match ev {
            Event::Start(tag) => {
                let (ns, local, qual, xmlns) = describe(&r, &tag)?;
                if open.is_empty() {
                    if seen {
                        return Err("multiple XML roots");
                    }
                    seen = true;
                    q = qual.clone();
                    rxmlns = xmlns;
                    rns = ns;
                    rlocal = local;
                    open.push(qual);
                } else if open.len() == 1 {
                    let own: BTreeSet<String> = xmlns.keys().cloned().collect();
                    pend = Some(Pending {
                        ns,
                        local,
                        start: bpos,
                        own,
                        qualified: qual.clone(),
                        xmlns,
                    });
                    pexts = Vec::new();
                    open.push(qual);
                } else if open.len() == 2 && in_extlst(&pend) {
                    let uri = unqualified_uri(&r, &tag)?;
                    let own: BTreeSet<String> = xmlns.keys().cloned().collect();
                    pext = Some(PendingExt {
                        ns,
                        local,
                        start: bpos,
                        own,
                        uri,
                    });
                    open.push(qual);
                } else {
                    open.push(qual);
                }
            }
            Event::Empty(tag) => {
                let (ns, local, qual, xmlns) = describe(&r, &tag)?;
                if open.is_empty() {
                    if seen {
                        return Err("multiple XML roots");
                    }
                    seen = true;
                    q = qual;
                    empty = true;
                    rend = apos;
                    rxmlns = xmlns;
                    rns = ns;
                    rlocal = local;
                } else if open.len() == 1 {
                    let own: BTreeSet<String> = xmlns.keys().cloned().collect();
                    if is_sml_extlst(&ns, &local) {
                        extlsts.push(ExtLst {
                            start: bpos,
                            end: apos,
                            is_empty: true,
                            qualified: qual,
                            xmlns,
                            end_tag_start: None,
                            exts: Vec::new(),
                        });
                    }
                    children.push(Child {
                        ns,
                        local,
                        start: bpos,
                        end: apos,
                        own,
                    });
                } else if open.len() == 2 && in_extlst(&pend) {
                    let uri = unqualified_uri(&r, &tag)?;
                    let own: BTreeSet<String> = xmlns.keys().cloned().collect();
                    pexts.push(ExtChild {
                        ns,
                        local,
                        start: bpos,
                        end: apos,
                        own,
                        uri,
                    });
                }
            }
            Event::End(tag) => {
                let name = tag.name().as_ref().to_owned();
                let Some(top) = open.pop() else {
                    return Err("malformed XML: stray end tag");
                };
                if top != name {
                    return Err("malformed XML: mismatched end tag");
                }
                if open.is_empty() {
                    rend_start = Some(bpos);
                    rend = apos;
                } else if open.len() == 1 {
                    if pext.is_some() {
                        return Err("malformed XML: unclosed ext");
                    }
                    let Some(p) = pend.take() else {
                        return Err("malformed XML: unexpected end");
                    };
                    let Pending {
                        ns,
                        local,
                        start,
                        own,
                        qualified,
                        xmlns,
                    } = p;
                    if is_sml_extlst(&ns, &local) {
                        extlsts.push(ExtLst {
                            start,
                            end: apos,
                            is_empty: false,
                            qualified,
                            xmlns,
                            end_tag_start: Some(bpos),
                            exts: std::mem::take(&mut pexts),
                        });
                    } else {
                        pexts.clear();
                    }
                    children.push(Child {
                        ns,
                        local,
                        start,
                        end: apos,
                        own,
                    });
                } else if open.len() == 2 && in_extlst(&pend) {
                    let Some(p) = pext.take() else {
                        return Err("malformed XML: unexpected end");
                    };
                    pexts.push(ExtChild {
                        ns: p.ns,
                        local: p.local,
                        start: p.start,
                        end: apos,
                        own: p.own,
                        uri: p.uri,
                    });
                }
            }
            Event::Text(text) => {
                let _ =
                    quick_xml::escape::unescape(text.as_ref()).map_err(|_| "invalid XML entity")?;
            }
            Event::GeneralRef(reference) => {
                if reference
                    .resolve_char_ref()
                    .map_err(|_| "invalid XML entity")?
                    .is_none()
                    && quick_xml::escape::resolve_predefined_entity(reference.as_ref()).is_none()
                {
                    return Err("unsupported XML entity");
                }
            }
            Event::DocType(_) => return Err("XML DTD is not supported"),
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen {
        return Err("missing XML root");
    }
    if !open.is_empty() || pend.is_some() || pext.is_some() {
        return Err("malformed XML: unclosed tags");
    }
    if rlocal != "worksheet" || rns.as_deref() != Some(SML_NS) {
        return Err("not a worksheet root (expected SML worksheet)");
    }
    rxmlns.entry(String::new()).or_default();
    Ok(Parsed {
        root_qualified: q,
        root_is_empty: empty,
        root_end: rend,
        root_end_tag_start: rend_start,
        root_xmlns: rxmlns,
        children,
        extlsts,
    })
}
fn describe(
    reader: &NsReader<&[u8]>,
    tag: &BytesStart<'_>,
) -> Result<(Option<String>, String, String, BTreeMap<String, String>), &'static str> {
    let (res, local) = reader.resolver().resolve_element(tag.name());
    let ns = match res {
        ResolveResult::Bound(n) => Some(n.as_ref().to_owned()),
        ResolveResult::Unbound => None,
        ResolveResult::Unknown(_) => return Err("unbound XML prefix"),
    };
    let local = local.as_ref().to_owned();
    let qual = tag.name().as_ref().to_owned();
    let mut xmlns: BTreeMap<String, String> = BTreeMap::new();
    for a in tag.attributes() {
        let a = a.map_err(|_| "invalid XML attribute")?;
        let v = a
            .normalized_value(quick_xml::XmlVersion::default())
            .map_err(|_| "invalid XML attribute value")?
            .into_owned();
        let key = a.key.as_ref();
        let prefix = if key == "xmlns" {
            String::new()
        } else if let Some(rest) = key.strip_prefix("xmlns:") {
            rest.to_owned()
        } else {
            if matches!(
                reader.resolver().resolve_attribute(a.key).0,
                ResolveResult::Unknown(_)
            ) {
                return Err("unbound XML prefix");
            }
            continue;
        };
        xmlns.insert(prefix, v);
    }
    Ok((ns, local, qual, xmlns))
}
fn unqualified_uri(
    reader: &NsReader<&[u8]>,
    tag: &BytesStart<'_>,
) -> Result<Option<String>, &'static str> {
    let mut uri = None;
    for a in tag.attributes() {
        let a = a.map_err(|_| "invalid XML attribute")?;
        let key = a.key.as_ref();
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        let (res, local) = reader.resolver().resolve_attribute(a.key);
        match res {
            ResolveResult::Unknown(_) => return Err("unbound XML prefix"),
            ResolveResult::Bound(_) => continue,
            ResolveResult::Unbound => {
                if local.as_ref() == "uri" {
                    uri = Some(
                        a.normalized_value(quick_xml::XmlVersion::default())
                            .map_err(|_| "invalid XML attribute value")?
                            .into_owned(),
                    );
                }
            }
        }
    }
    Ok(uri)
}
fn inject_xmlns(raw: &[u8], bindings: &BTreeMap<String, String>) -> Vec<u8> {
    if bindings.is_empty() {
        return raw.to_vec();
    }
    let Some(end) = find_start_tag_end(raw) else {
        return raw.to_vec();
    };
    if end == 0 {
        return raw.to_vec();
    }
    let at = if raw[end - 1] == b'/' { end - 1 } else { end };
    let mut add = String::new();
    for (p, u) in bindings {
        if p.is_empty() {
            add.push_str(&format!(" xmlns=\"{}\"", escape(u)));
        } else {
            add.push_str(&format!(" xmlns:{p}=\"{}\"", escape(u)));
        }
    }
    let mut out = Vec::with_capacity(raw.len() + add.len());
    out.extend_from_slice(&raw[..at]);
    out.extend_from_slice(add.as_bytes());
    out.extend_from_slice(&raw[at..]);
    out
}
fn find_start_tag_end(raw: &[u8]) -> Option<usize> {
    let (mut s, mut d) = (false, false);
    for (i, &b) in raw.iter().enumerate() {
        if s {
            if b == b'\'' {
                s = false;
            }
        } else if d {
            if b == b'"' {
                d = false;
            }
        } else {
            match b {
                b'\'' => s = true,
                b'"' => d = true,
                b'>' => return Some(i),
                _ => {}
            }
        }
    }
    None
}
fn escape(value: &str) -> String {
    let mut o = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\r' => o.push_str("&#13;"),
            '\n' => o.push_str("&#10;"),
            '\t' => o.push_str("&#9;"),
            _ => o.push(c),
        }
    }
    o
}
