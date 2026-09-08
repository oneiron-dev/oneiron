//! CGI response framing, observed-ref narrowing, and the exchange-to-report
//! landing commit.

use std::io::{self, Read};
use std::path::Path;
use std::process::ChildStdout;
use std::sync::Arc;

use super::door::DoorAdmissionStamp;
use super::evidence::{RefUpdate, landing_pin, local_repo_ref, receive_pack_provenance_refused};
use super::intent::{ReceivePackRefResult, ReceivePackRefStatus};
use super::paths::{SERVE_MAX_CGI_HEADER_BYTES, SERVE_STREAM_CHUNK_BYTES, serve_failed};
use super::serve::{ServeExchange, ServeReport, ServeSink};
use super::serve_cmd::ServeRequest;
use crate::Vault;
use crate::error::{Error, Result};
use crate::git_wire::{GitRefName, GitWire};

/// Parses the CGI header block, then streams the body through untouched.
pub(super) fn stream_response(
    mut stdout: ChildStdout,
    sink: &mut dyn ServeSink,
) -> Result<(u16, u64)> {
    let (status, headers, mut carry) = read_cgi_headers(&mut stdout)?;
    sink.begin(status, &headers)?;
    let mut total = 0_u64;
    if !carry.is_empty() {
        sink.write_chunk(&carry)?;
        total = total.saturating_add(carry.len() as u64);
        carry.clear();
    }
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                sink.write_chunk(&buffer[..read])?;
                total = total.saturating_add(read as u64);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok((status, total))
}

type CgiHeaderBlock = (u16, Vec<(String, String)>, Vec<u8>);

fn read_cgi_headers(stdout: &mut ChildStdout) -> Result<CgiHeaderBlock> {
    let mut raw = Vec::new();
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    let split = loop {
        if let Some(split) = header_terminator(&raw) {
            break split;
        }
        if raw.len() > SERVE_MAX_CGI_HEADER_BYTES {
            return Err(serve_failed(
                "git http-backend produced an oversized header",
            ));
        }
        match stdout.read(&mut buffer) {
            Ok(0) => {
                return Err(serve_failed(
                    "git http-backend produced no CGI header block",
                ));
            }
            Ok(read) => raw.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
    };
    let body = raw.split_off(split.1);
    raw.truncate(split.0);
    let (status, headers) = parse_cgi_headers(&raw)?;
    Ok((status, headers, body))
}

/// Returns `(header_end, body_start)` for whichever terminator the backend used.
fn header_terminator(raw: &[u8]) -> Option<(usize, usize)> {
    let crlf = find_subsequence(raw, b"\r\n\r\n").map(|at| (at, at + 4));
    let lf = find_subsequence(raw, b"\n\n").map(|at| (at, at + 2));
    match (crlf, lf) {
        (Some(crlf), Some(lf)) if lf.0 < crlf.0 => Some(lf),
        (Some(crlf), _) => Some(crlf),
        (None, found) => found,
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_cgi_headers(raw: &[u8]) -> Result<(u16, Vec<(String, String)>)> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| serve_failed("git http-backend CGI headers must be UTF-8"))?;
    let mut status = 200_u16;
    let mut headers = Vec::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Status") {
            status = value
                .split(' ')
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or_else(|| serve_failed("git http-backend produced an unparsable status"))?;
            continue;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    Ok((status, headers))
}

/// Narrows the door window's proposed updates to the ones the repository
/// actually carries now.
///
/// The landing journals what the origin's receive-pack DID; it is never an
/// independent writer. A ref the backend declined after the door window (a
/// non-fast-forward, a per-ref refusal) is observably unmoved, so it is
/// dropped here instead of being published by the origin behind git's back.
///
/// A deletion is narrowed by that same one comparison rather than by a second
/// rule: its `new_oid` is `None`, so it survives exactly when the ref is
/// observably ABSENT, and a delete the backend declined is dropped like any
/// other unrealized move. Deletions are a real outcome and are journaled like
/// any other — a delete-only push mutates the repository, so it owes a receipt.
pub(super) fn realized_updates(
    vault: &Vault,
    repo_dir: &Path,
    proposed: &[RefUpdate],
) -> Result<Vec<RefUpdate>> {
    let Some(pin) = landing_pin(proposed) else {
        // No proposed ref carries a value in either direction, so there is no
        // commit that names this object store and nothing to journal.
        return Ok(Vec::new());
    };
    let repo = local_repo_ref(repo_dir, pin)?;
    let wire = GitWire::new(vault)?;
    let handle = match wire.open_repo(repo, repo_dir) {
        Ok(handle) => handle,
        Err(error) => {
            let mut existing = None;
            for old in proposed.iter().filter_map(|update| update.old_oid.as_ref()) {
                if let Ok(handle) = wire.open_repo(local_repo_ref(repo_dir, old)?, repo_dir) {
                    existing = Some(handle);
                    break;
                }
            }
            existing.ok_or(error)?
        }
    };
    let names = proposed
        .iter()
        .map(|update| GitRefName::parse_full(update.name.clone()))
        .collect::<Result<Vec<_>>>()?;
    let observed = wire.read_refs(&handle, &names)?;
    Ok(proposed
        .iter()
        .zip(observed)
        .filter_map(|(update, seen)| (update.new_oid == seen.oid).then(|| update.clone()))
        .collect())
}

pub(super) fn finish_serve(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    repo_dir: &Path,
    admission: Option<DoorAdmissionStamp>,
    exchange: ServeExchange,
) -> Result<ServeReport> {
    let mut report = ServeReport {
        status: exchange.status,
        admission,
        door: exchange.door,
        outcome: None,
        landing: None,
        ref_results: Vec::new(),
    };
    if !request.is_receive_pack() || !report.door.admitted() {
        return Ok(report);
    }
    let stamp = report
        .admission
        .as_ref()
        .ok_or_else(|| receive_pack_provenance_refused("admission is absent"))?;
    let (key, mut intent) = vault
        .receive_pack_intents(repo_dir)?
        .into_iter()
        .find(|(_, intent)| intent.operation_id == stamp.operation_id.to_hex())
        .ok_or_else(|| receive_pack_provenance_refused("pre-effect intent is absent"))?;
    // Never replace the counters of an already-observed operation. Commit the
    // measured totals before the observer so every recovery uses the same bytes.
    if intent.transport_bytes.is_some() || intent.refs.iter().any(|entry| entry.observed) {
        return Err(receive_pack_provenance_refused(
            "transport already finalized",
        ));
    }
    intent.transport_bytes = Some((exchange.request_bytes, exchange.response_bytes));
    vault.save_receive_pack_intent(&key, &intent)?;
    (report.outcome, report.landing) = vault
        .resume_receive_pack_intent(&key, &mut intent)
        .unwrap_or_default();
    report.ref_results = intent
        .refs
        .iter()
        .map(|entry| ReceivePackRefResult {
            name: entry.name.clone(),
            status: entry.status,
        })
        .collect();
    if report
        .ref_results
        .iter()
        .any(|entry| entry.status != ReceivePackRefStatus::Published)
    {
        // This is not a whole-push success. The server rewrites Git's statuses
        // using ref_results, while the operation retains every unfinished ref.
        report.landing = None;
    }
    Ok(report)
}
