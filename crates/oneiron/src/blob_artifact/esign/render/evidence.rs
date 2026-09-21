//! Audit replay and certificate/complete-trail PDF appendices.
use super::fields::{op, text};
use super::*;
use qrcode::{Color, QrCode};

pub(super) fn evidence(request: &PdfPreparation<'_>) -> Result<([u8; 32], Vec<String>)> {
    reference(request.document_ref).map_err(|_| PdfPreparationError::InvalidEvidence)?;
    if request.audit.is_empty()
        || request.audit.len() > 10_000
        || request.item as usize >= request.state.document.items.len()
        || !request.state.ready_to_seal()
    {
        return Err(PdfPreparationError::InvalidEvidence);
    }
    // Bound canonical encoding before cloning or replaying caller data.
    let mut remaining = 4 * 1024 * 1024;
    let mut encoded_rows = Vec::new();
    for row in request.audit {
        let mut buffer = AuditBuffer {
            bytes: Vec::new(),
            remaining,
        };
        serde_json::to_writer(&mut buffer, row).map_err(|_| PdfPreparationError::Limit)?;
        remaining -= buffer.bytes.len();
        encoded_rows.push(buffer.bytes);
    }
    let EsignEvent::Drafted { document } = &request.audit[0].event else {
        return Err(PdfPreparationError::InvalidEvidence);
    };
    let mut state = EsignState::draft(document.clone(), request.audit[0].at)
        .map_err(|_| PdfPreparationError::InvalidEvidence)?;
    let (mut previous, mut at) = ([0; 32], 0);
    let mut lines = Vec::new();
    for (i, (row, bytes)) in request.audit.iter().zip(encoded_rows).enumerate() {
        if row.sequence != i as u64
            || row.previous_sha256 != previous
            || row.at < at
            || row.actor.actor.is_empty()
            || row.actor.actor.len() > 4096
            || row.actor.ip.as_ref().is_some_and(|v| v.len() > 256)
            || row
                .actor
                .user_agent
                .as_ref()
                .is_some_and(|v| v.len() > 4096)
        {
            return Err(PdfPreparationError::InvalidEvidence);
        }
        if i > 0 {
            state
                .apply(&row.event, row.at)
                .map_err(|_| PdfPreparationError::InvalidEvidence)?;
        }
        previous = Sha256::digest(&bytes).into();
        at = row.at;
        if request.state.document.full_trail_appendix {
            lines.push(String::from_utf8(bytes).map_err(|_| PdfPreparationError::Encoding)?);
        }
    }
    if state != *request.state {
        return Err(PdfPreparationError::InvalidEvidence);
    }
    Ok((previous, lines))
}
struct AuditBuffer {
    bytes: Vec<u8>,
    remaining: usize,
}
impl std::io::Write for AuditBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("audit limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|v| format!("{v:02x}")).collect()
}
fn escaped(value: &str) -> String {
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
        .collect()
}
fn append_page(
    out: &mut Document,
    parent: ObjectId,
    font: ObjectId,
    operations: Vec<Operation>,
) -> Result<ObjectId> {
    let content = out.add_object(Stream::new(
        Dictionary::new(),
        Content { operations }.encode()?,
    ));
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
) -> Result<()> {
    let wrapped: Vec<_> = lines
        .iter()
        .flat_map(|l| {
            escaped(l)
                .as_bytes()
                .chunks(90)
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect::<Vec<_>>()
        })
        .collect();
    if wrapped.len() > 50_000 {
        return Err(PdfPreparationError::Limit);
    }
    for group in wrapped.chunks(56) {
        let mut ops = Vec::new();
        for (i, line) in group.iter().enumerate() {
            text(&mut ops, b"F", line, 36.0, 752.0 - 12.0 * i as f64, 10.0);
        }
        kids.push(append_page(out, parent, font, ops)?.into());
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
pub(super) fn certificate(
    out: &mut Document,
    parent: ObjectId,
    font: ObjectId,
    request: &PdfPreparation<'_>,
    evidence: ([u8; 32], [u8; 32], Vec<String>),
    kids: &mut Vec<Object>,
) -> Result<()> {
    let (original, chain, trail) = evidence;
    // Never fetch this URL or invent a deployment hostname. Deliberately a
    // narrow ASCII HTTPS grammar; reject userinfo, non-capability fragments and whitespace.
    let url = request.canonical_url;
    let rest = url
        .strip_prefix("https://")
        .ok_or(PdfPreparationError::InvalidCanonicalUrl)?;
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
        return Err(PdfPreparationError::InvalidCanonicalUrl);
    }
    let qr = QrCode::new(url.as_bytes()).map_err(|_| PdfPreparationError::InvalidCanonicalUrl)?;
    let item = &request.state.document.items[request.item as usize];
    let lines = [
        "esign_certificate.v1".to_owned(),
        format!("document: {}", request.document_ref),
        format!("item: {}", request.item),
        format!("artifact: {}", item.artifact_ref),
        format!("original_version: {}", item.original_version),
        format!("original_sha256: {}", hex(&original)),
        format!("audit_chain_sha256: {}", hex(&chain)),
        format!("audit_rows: {}", request.audit.len()),
        format!(
            "outcome: {}",
            if request.state.rejection.is_some() {
                "rejected"
            } else {
                "completed"
            }
        ),
    ];
    let mut ops = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        text(&mut ops, b"F", line, 36.0, 752.0 - 16.0 * i as f64, 10.0);
    }
    // Four-module quiet zone on all sides; vector black modules on white.
    let unit = 240.0 / (qr.width() + 8) as f64;
    op(&mut ops, "g", &[1.0]);
    op(&mut ops, "re", &[36.0, 256.0, 240.0, 240.0]);
    op(&mut ops, "f", &[]);
    op(&mut ops, "g", &[0.0]);
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
                );
            }
        }
    }
    op(&mut ops, "f", &[]);
    kids.push(append_page(out, parent, font, ops)?.into());
    let mut details = vec![
        format!("title: {}", request.state.document.title),
        format!("canonical_url: {url}"),
    ];
    if let Some(reason) = &request.state.rejection {
        details.push(format!("rejection: {reason}"));
    }
    for recipient in &request.state.document.recipients {
        details.push(format!(
            "recipient: {} name: {} email: {}",
            recipient.id, recipient.name, recipient.email
        ));
    }
    for signature in request.state.signatures.values() {
        details.push(format!(
            "field: {} recipient: {} at: {}",
            signature.field, signature.recipient, signature.at
        ));
    }
    append_lines(out, parent, font, &details, kids)?;
    if !trail.is_empty() {
        append_lines(out, parent, font, &["esign_full_trail.v1".to_owned()], kids)?;
        append_lines(out, parent, font, &trail, kids)?;
    }
    Ok(())
}
