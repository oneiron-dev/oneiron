//! Ported certificate/complete-trail PDF appendices (FIX 7980/8157).
//!
//! Ports the engine's `render/evidence` `certificate` (with its `hex`,
//! `escaped`, `append_page`, `append_lines`, and `canonical_host` helpers)
//! into the organ admission model. The audit-chain replay (`evidence()`)
//! stays engine-side: the host runs it there and lents its checked output,
//! so this file takes lent scalars, never the engine model (F4).
//!
//! Behavior-identical except admission and bounds: every string, vector,
//! operation, dictionary entry, and fresh-document object is admitted
//! against the call's operation ledger first (via [`WorkLimits`]), never
//! the engine `Stage` (the certificate takes no `Stage`; the ledger is
//! added for the organ's buffers). The URL/QR checks are verbatim decoder
//! bounds ([`InputInvalidCode::InvalidCanonicalUrl`]) and the QR renders
//! organ-side. No per-stream codec bound exists here, so no refusal is
//! dropped to an admission (contrast `work_streams`): value-shape refusals
//! stay engine-side and their checked scalars are lent in, marked below.
//!
//! Reuses `work_burn`'s admitted [`op`]/[`text`] rather than duplicating
//! them.

use std::mem::size_of;

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use qrcode::{Color, QrCode};

use super::work::{WorkError, WorkLimits};
use super::work_burn::{op, text};
use crate::error::InputInvalidCode;
use crate::memory::{MemoryLedger, SealMemoryRefusal};

type Result<T> = std::result::Result<T, WorkError>;

/// One recipient's lent identity row, as the engine's `EsignRecipient`
/// fields the certificate prints: the host validates the row engine-side
/// and the replay binds it to the sealed state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WorkRecipient<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub email: &'a str,
    pub natural_person: Option<&'a str>,
}

/// One signature's lent row, as the engine's `SignatureRow` fields the
/// certificate prints: the host validates the shape engine-side.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WorkSignature<'a> {
    pub field: &'a str,
    pub recipient: &'a str,
    pub at: u64,
}

/// The certificate's lent request scalars, as the engine's `PdfPreparation`
/// fields `certificate` reads: the host runs the audit-chain replay
/// engine-side and lents its checked projection. `artifact_ref` and
/// `original_version` are the replay-bound `items[item]` row (no organ-side
/// indexing); `audit_rows` is the replayed audit's length; `rejection` is
/// the sealed state's outcome; `signatures` iterate in field-id order, as
/// the engine's signatures map does. `canonical_url` is NOT checked
/// engine-side: its narrow HTTPS grammar is verified organ-side, verbatim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CertificateRequest<'a> {
    pub document_ref: &'a str,
    pub item: u32,
    pub canonical_url: &'a str,
    pub artifact_ref: &'a str,
    pub original_version: u64,
    pub title: &'a str,
    pub audit_rows: usize,
    pub rejection: Option<&'a str>,
    pub recipients: &'a [WorkRecipient<'a>],
    pub signatures: &'a [WorkSignature<'a>],
}

/// The certificate + details + optional full-trail appendix pages, exactly
/// as the engine's `evidence::certificate`: the narrow HTTPS capability-URL
/// check, the organ-side QR, the nine-line certificate page, the details
/// pages, and the full-trail pages. Every buffer is admitted first.
pub(crate) fn certificate(
    out: &mut Document,
    parent: ObjectId,
    font: ObjectId,
    // organ: lent by the host, checked engine-side
    request: &CertificateRequest<'_>,
    // organ: lent by the host, checked engine-side (chain + trail are the
    // engine replay's checked output; original is the caller's sha256 of the
    // lent input, as the engine binds it)
    evidence: ([u8; 32], [u8; 32], &[String]),
    kids: &mut Vec<Object>,
    limits: &WorkLimits<'_>,
) -> Result<()> {
    let (original, chain, trail) = evidence;
    // Never fetch this URL or invent a deployment hostname. Deliberately a
    // narrow ASCII HTTPS grammar; reject userinfo, non-capability fragments and whitespace.
    let url = request.canonical_url;
    let rest = url
        .strip_prefix("https://")
        .ok_or(WorkError::Invalid(InputInvalidCode::InvalidCanonicalUrl))?;
    let fragment_ok = rest.split_once('#').is_none_or(|(_, token)| {
        token.len() == 64
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    let host = rest.split('/').next().unwrap_or("");
    if url.len() > 2048
        || host.is_empty()
        || !rest.contains('/')
        || !fragment_ok
        || rest.contains(['@', '\\'])
        || !canonical_host(host)
        || url.bytes().any(|b| !(33..=126).contains(&b))
    {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidCanonicalUrl));
    }
    let qr = QrCode::new(url.as_bytes())
        .map_err(|_| WorkError::Invalid(InputInvalidCode::InvalidCanonicalUrl))?;
    let lines = [
        admitted("esign_certificate.v1".to_owned(), limits)?,
        admitted(format!("document: {}", request.document_ref), limits)?,
        admitted(format!("item: {}", request.item), limits)?,
        admitted(format!("artifact: {}", request.artifact_ref), limits)?,
        admitted(
            format!("original_version: {}", request.original_version),
            limits,
        )?,
        admitted(
            format!("original_sha256: {}", hex(&original, limits)?),
            limits,
        )?,
        admitted(
            format!("audit_chain_sha256: {}", hex(&chain, limits)?),
            limits,
        )?,
        admitted(format!("audit_rows: {}", request.audit_rows), limits)?,
        admitted(
            format!(
                "outcome: {}",
                if request.rejection.is_some() {
                    "rejected"
                } else {
                    "completed"
                }
            ),
            limits,
        )?,
    ];
    let mut ops = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        text(
            &mut ops,
            b"F",
            line,
            36.0,
            752.0 - 16.0 * i as f64,
            10.0,
            limits,
        )?;
    }
    // Four-module quiet zone on all sides; vector black modules on white.
    let unit = 240.0 / (qr.width() + 8) as f64;
    op(&mut ops, "g", &[1.0], limits)?;
    op(&mut ops, "re", &[36.0, 256.0, 240.0, 240.0], limits)?;
    op(&mut ops, "f", &[], limits)?;
    op(&mut ops, "g", &[0.0], limits)?;
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr[(x, y)] == Color::Dark {
                op(
                    &mut ops,
                    "re",
                    &[
                        36.0 + (x + 4) as f64 * unit,
                        256.0 + (qr.width() + 3 - y) as f64 * unit,
                        unit,
                        unit,
                    ],
                    limits,
                )?;
            }
        }
    }
    op(&mut ops, "f", &[], limits)?;
    let page = append_page(out, parent, font, ops, limits)?;
    push(limits.ledger, kids, page.into())?;
    let mut details = Vec::new();
    push_detail(&mut details, format!("title: {}", request.title), limits)?;
    push_detail(&mut details, format!("canonical_url: {url}"), limits)?;
    if let Some(reason) = &request.rejection {
        push_detail(&mut details, format!("rejection: {reason}"), limits)?;
    }
    for recipient in request.recipients {
        let mut line = format!(
            "recipient: {} name: {} email: {}",
            recipient.id, recipient.name, recipient.email
        );
        limits
            .ledger
            .admit_len::<u8>(line.len())
            .map_err(WorkError::Memory)?;
        // The law that kept this signature with a natural person, as the
        // sender named it.
        if let Some(basis) = &recipient.natural_person {
            let tail = format!(" natural_person: {basis}");
            limits
                .ledger
                .admit_len::<u8>(tail.len())
                .map_err(WorkError::Memory)?;
            line.push_str(&tail);
            let tail_len = tail.len();
            drop(tail);
            limits.ledger.release_admitted(wide(tail_len));
        }
        push(limits.ledger, &mut details, line)?;
    }
    for signature in request.signatures {
        push_detail(
            &mut details,
            format!(
                "field: {} recipient: {} at: {}",
                signature.field, signature.recipient, signature.at
            ),
            limits,
        )?;
    }
    append_lines(out, parent, font, &details, kids, limits)?;
    if !trail.is_empty() {
        let head = admitted("esign_full_trail.v1".to_owned(), limits)?;
        append_lines(out, parent, font, &[head], kids, limits)?;
        append_lines(out, parent, font, trail, kids, limits)?;
    }
    Ok(())
}

fn hex(value: &[u8; 32], limits: &WorkLimits<'_>) -> Result<String> {
    admitted(value.iter().map(|v| format!("{v:02x}")).collect(), limits)
}

fn escaped(value: &str, limits: &WorkLimits<'_>) -> Result<String> {
    admitted(
        value
            .chars()
            .flat_map(|c| {
                if c == '\\' {
                    "\\\\".to_owned()
                } else if (' '..='~').contains(&c) {
                    c.to_string()
                } else {
                    c.escape_default().to_string()
                }
                .chars()
                .collect::<Vec<_>>()
            })
            .collect(),
        limits,
    )
}

fn append_page(
    out: &mut Document,
    parent: ObjectId,
    font: ObjectId,
    operations: Vec<Operation>,
    limits: &WorkLimits<'_>,
) -> Result<ObjectId> {
    let encoded = Content { operations }
        .encode()
        .map_err(|err| lopdf_error(limits, err))?;
    limits
        .ledger
        .admit_len::<u8>(encoded.len())
        .map_err(WorkError::Memory)?;
    object_insert(limits.ledger)?;
    let content = out.add_object(Stream::new(Dictionary::new(), encoded));
    page_dict_insert(limits.ledger)?;
    limits
        .ledger
        .admit_len::<Object>(4)
        .map_err(WorkError::Memory)?;
    object_insert(limits.ledger)?;
    Ok(out.add_object(dictionary! { "Type" => "Page", "Parent" => parent,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F" => font } }, "Contents" => content }))
}

fn append_lines(
    out: &mut Document,
    parent: ObjectId,
    font: ObjectId,
    lines: &[String],
    kids: &mut Vec<Object>,
    limits: &WorkLimits<'_>,
) -> Result<()> {
    let mut wrapped: Vec<String> = Vec::new();
    for line in lines {
        let clean = escaped(line, limits)?;
        for chunk in clean.as_bytes().chunks(90) {
            let owned = String::from_utf8_lossy(chunk).into_owned();
            limits
                .ledger
                .admit_len::<u8>(owned.len())
                .map_err(WorkError::Memory)?;
            push(limits.ledger, &mut wrapped, owned)?;
        }
        let clean_len = clean.len();
        drop(clean);
        limits.ledger.release_admitted(wide(clean_len));
    }
    for group in wrapped.chunks(56) {
        let mut ops = Vec::new();
        for (i, line) in group.iter().enumerate() {
            text(
                &mut ops,
                b"F",
                line,
                36.0,
                752.0 - 12.0 * i as f64,
                10.0,
                limits,
            )?;
        }
        let page = append_page(out, parent, font, ops, limits)?;
        push(limits.ledger, kids, page.into())?;
    }
    Ok(())
}

fn canonical_host(authority: &str) -> bool {
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().is_none_or(|port| port == 0)
        {
            return false;
        }
        host
    } else {
        authority
    };
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse::<std::net::Ipv4Addr>().is_ok();
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Admit a fresh string's bytes, then hand it back.
fn admitted(value: String, limits: &WorkLimits<'_>) -> Result<String> {
    limits
        .ledger
        .admit_len::<u8>(value.len())
        .map_err(WorkError::Memory)?;
    Ok(value)
}

/// Admit a details line's bytes and push it.
fn push_detail(details: &mut Vec<String>, line: String, limits: &WorkLimits<'_>) -> Result<()> {
    limits
        .ledger
        .admit_len::<u8>(line.len())
        .map_err(WorkError::Memory)?;
    push(limits.ledger, details, line)
}

/// A lopdf failure as the organ reads it: a kept memory refusal as itself,
/// anything else as a malformed PDF, never the reverse.
fn lopdf_error(limits: &WorkLimits<'_>, err: lopdf::Error) -> WorkError {
    limits.ledger.refusal_of(&err).map_or(
        WorkError::Invalid(InputInvalidCode::MalformedPdf),
        WorkError::Memory,
    )
}

/// A length as the ledger counts bytes.
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn floor(bytes: usize) -> SealMemoryRefusal {
    SealMemoryRefusal::Floor {
        needed: u64::try_from(bytes).unwrap_or(u64::MAX),
        available: 0,
    }
}

fn layout_bytes<T>(len: usize) -> Option<usize> {
    len.checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
}

/// Fallibly grow one vector under the call's operation ledger, with the
/// same double-capacity growth and old-buffer release as `admitted`.
fn reserve<T>(ledger: &MemoryLedger, output: &mut Vec<T>, additional: usize) -> Result<()> {
    let needed = output
        .len()
        .checked_add(additional)
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    if needed <= output.capacity() {
        return Ok(());
    }
    let old_capacity = output.capacity();
    let target = old_capacity.saturating_mul(2).max(needed);
    let bytes = layout_bytes::<T>(target).ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<T>(target).map_err(WorkError::Memory)?;
    output
        .try_reserve_exact(target - output.len())
        .map_err(|_| WorkError::Memory(floor(bytes)))?;
    let old_bytes = layout_bytes::<T>(old_capacity).unwrap_or(0);
    ledger.release_admitted(u64::try_from(old_bytes).unwrap_or(u64::MAX));
    Ok(())
}

fn push<T>(ledger: &MemoryLedger, output: &mut Vec<T>, value: T) -> Result<()> {
    reserve(ledger, output, 1)?;
    output.push(value);
    Ok(())
}

const fn btree_node_bytes<K, V>() -> usize {
    11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64
}

const fn btree_entry_bytes<K, V>() -> usize {
    btree_node_bytes::<K, V>().div_ceil(5)
}

/// One fresh `Document` object: the objects-map entry share. The object's
/// heap (stream bytes, dictionaries) is admitted where it is built.
fn object_insert(ledger: &MemoryLedger) -> Result<()> {
    ledger
        .admit_len::<u8>(btree_entry_bytes::<ObjectId, Object>())
        .map_err(WorkError::Memory)
}

/// One appendix page dictionary built whole: 7 entries across the page,
/// Resources, and Font maps, their 40 key bytes, the 4 `Page` name bytes,
/// and the 3 map nodes. The MediaBox array and stream bytes are admitted
/// where they are built.
fn page_dict_insert(ledger: &MemoryLedger) -> Result<()> {
    let bytes = btree_entry_bytes::<Vec<u8>, Object>()
        .checked_mul(7)
        .and_then(|shares| {
            shares.checked_add(btree_node_bytes::<Vec<u8>, Object>().checked_mul(3)?)
        })
        .and_then(|shares| shares.checked_add(40))
        .and_then(|shares| shares.checked_add(4))
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<u8>(bytes).map_err(WorkError::Memory)
}
