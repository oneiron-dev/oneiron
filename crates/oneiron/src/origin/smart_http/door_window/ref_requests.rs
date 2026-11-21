//! Hook request parsing and ref-name admission.

use super::*;

/// Why this push cannot be landed, one reason per offending name, empty when
/// every proposed move is one the landing can journal.
///
/// This is the pre-move half of the landing's own rule. `RefUpdate::publication`
/// and `realized_updates` both parse these names with [`GitRefName::parse_full`]
/// and both collect WHOLE, so a single name outside the GitWire grammar turns
/// the landing into an error — and by then `git receive-pack` has moved the
/// refs, leaving a mutated repository with no receipt. Deciding here, while the
/// hook is still blocked and the objects are still quarantined, is what keeps
/// "git moved it" and "the origin journaled it" the same set.
///
/// Every rule below is one the landing enforces anyway; none of them narrows
/// what a legal push may do:
///
/// - `refs/replace/*` is refused outright (see [`ORIGIN_REFUSED_REF_PREFIX`]):
///   the landing would publish it, and what it publishes is a rewrite of what
///   every later scan of this repository reads.
/// - A name outside the GitWire ref grammar is refused, because
///   [`GitRefName::parse_full`] is what the landing must parse it with.
/// - A name proposed twice is refused, because the landing journals one
///   outcome per name.
///
/// How many refs a push moves is never a reason (rule 5): the landing
/// publishes them one at a time. Every name is checked; only the first
/// reasons are kept as text ([`RetainedReasons`]).
pub(in crate::origin::smart_http) fn unlandable_ref_reasons(
    updates: &[RefUpdate],
) -> RetainedReasons {
    let mut reasons = RetainedReasons::default();
    let mut seen = std::collections::HashSet::with_capacity(updates.len());
    for update in updates {
        let why = if update.name.starts_with(ORIGIN_REFUSED_REF_PREFIX) {
            "this origin never serves a replacement ref"
        } else if GitRefName::parse_full(update.name.clone()).is_err() {
            "not a ref name this origin can journal"
        } else if !seen.insert(update.name.as_str()) {
            "proposed twice in one push"
        } else {
            continue;
        };
        reasons.push_with(|| format!("{}: {why}", printable_ref_name(&update.name)));
    }
    reasons
}

/// The offending name as it may appear in a refusal the client will read.
///
/// A refusal names the ref and nothing else — no pushed byte and no value ever
/// reaches this string. The name itself is client-supplied, so it is bounded
/// and stripped of anything that is not printable ASCII before it is echoed.
pub(in crate::origin::smart_http) fn printable_ref_name(name: &str) -> String {
    let mut printable = name
        .chars()
        .take(DOOR_REFUSAL_NAME_CHARS)
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect::<String>();
    if name.chars().nth(DOOR_REFUSAL_NAME_CHARS).is_some() {
        printable.push_str("...");
    }
    printable
}

pub(in crate::origin::smart_http) fn parse_door_request(bytes: &[u8]) -> Result<DoorWindowRequest> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| serve_failed("door request must be UTF-8".to_owned()))?;
    let mut quarantine_path = None;
    let mut ref_updates = Vec::new();
    let mut rewritten_refs = Vec::new();
    let mut symbolic_refs = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("quarantine ") {
            if !rest.is_empty() {
                quarantine_path = Some(PathBuf::from(rest));
            }
        } else if let Some(rest) = line.strip_prefix("ref ") {
            ref_updates.push(parse_ref_update(rest)?);
        } else if let Some(rest) = line.strip_prefix("rewrite ") {
            rewritten_refs.push(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("symref ") {
            // A ref name holds no space (git's ref-name rules).
            let (symbolic, referent) = rest
                .split_once(' ')
                .ok_or_else(|| serve_failed("door request has a malformed symref line"))?;
            symbolic_refs.push((symbolic.to_owned(), referent.to_owned()));
        }
    }
    Ok(DoorWindowRequest {
        quarantine_path,
        ref_updates,
        rewritten_refs,
        symbolic_refs,
    })
}

fn parse_ref_update(line: &str) -> Result<RefUpdate> {
    let mut parts = line.split(' ');
    let old = parts
        .next()
        .ok_or_else(|| serve_failed("door request ref line has no old oid"))?;
    let new = parts
        .next()
        .ok_or_else(|| serve_failed("door request ref line has no new oid"))?;
    let name = parts
        .next()
        .ok_or_else(|| serve_failed("door request ref line has no ref name"))?;
    // The name is the LAST field, so a line with a fourth one describes a name
    // this parse would truncate — and a truncated name is a name the door would
    // decide while git moved a different one. Git's own ref grammar has no
    // space in it, so this is a fault, and a fault here is a refusal.
    if parts.next().is_some() {
        return Err(serve_failed("door request ref line has a spaced ref name"));
    }
    Ok(RefUpdate {
        name: name.to_owned(),
        old_oid: parse_optional_oid(old)?,
        new_oid: parse_optional_oid(new)?,
    })
}

/// The all-zero oid is git's "absent", and the canonical [`GitOid`] refuses it
/// by construction, so absence is `None` and never a second oid type.
pub(in crate::origin::smart_http) fn parse_optional_oid(value: &str) -> Result<Option<GitOid>> {
    if value.bytes().all(|byte| byte == b'0') {
        return Ok(None);
    }
    Ok(Some(GitOid::parse_hex(value.to_ascii_lowercase())?))
}
