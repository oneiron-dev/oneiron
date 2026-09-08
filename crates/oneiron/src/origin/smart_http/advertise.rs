//! The publication-gated ref-advertisement rewrite: pkt-line state machine and
//! keep policy.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::evidence::local_repo_ref;
use super::paths::serve_failed;
use super::serve::ServeSink;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName, GitWire};
use crate::origin::lfs::lfs_repo_id;

/// The hex length of a SHA-1 object id, which is the only width this wire
/// carries.
const ADVERTISED_OID_HEX_LEN: usize = 40;

/// The largest pkt-line this gate will hold.
///
/// Only ONE line is ever held for a decision; this bound covers the partial
/// line left at a chunk boundary, so a backend that never terminates a
/// pkt-line cannot grow the carry without limit.
const SERVE_MAX_PKT_LINE_BYTES: usize = 65_524;

/// The all-zero object id the empty-repository advertisement uses.
pub(super) const ADVERTISED_ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// The pseudo-ref an advertisement with no refs carries its capabilities on.
pub(super) const ADVERTISED_CAPABILITIES_REF: &str = "capabilities^{}";

/// One pkt-line, or the flush that ends a section.
pub(super) enum PktLine {
    Flush,
    Data(Vec<u8>),
}

/// Which section of the advertisement the gate is reading.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AdvertisementPhase {
    /// The `# service=...` banner and its flush, passed through verbatim.
    Banner,
    /// The ref list, which is what this gate exists for.
    Refs,
    /// Anything after the ref list's flush, passed through verbatim.
    Trailer,
}

/// The publication projection for one served repository.
///
/// Resolved ONCE per advertisement, from the first object id the backend
/// printed: [`GitWire::open_repo`] proves a repository against a commit it
/// holds, and an advertised ref value is by construction such a commit. The
/// advertisement has no earlier pin to offer.
struct AdvertisementProjection {
    repo_id: EntityId,
    published: Vec<(GitRefName, GitOid)>,
}

/// The one place a served ref list is decided.
///
/// Every ref the origin advertises must appear in
/// [`Vault::published_origin_refs`]. A seeded repository still needs an explicit
/// publication; raw refs and failed projection reads never grant visibility.
/// `HEAD` survives only when its object is projected, and the all-zero
/// `capabilities^{}` line carries no object. Keep-refs are internal roots (RA4)
/// and are always omitted.
pub(super) struct AdvertisedRefGate<'a> {
    vault: Arc<Vault>,
    repo_dir: PathBuf,
    inner: &'a mut dyn ServeSink,
    /// Off until the CGI headers prove this really is an advertisement.
    gating: bool,
    carry: Vec<u8>,
    phase: AdvertisementPhase,
    /// The capability suffix, detached from whichever ref line carried it.
    capabilities: Option<Vec<u8>>,
    emitted_ref: bool,
    projection: Option<AdvertisementProjection>,
    unresolved: bool,
}

impl<'a> AdvertisedRefGate<'a> {
    pub(super) fn new(vault: &Arc<Vault>, repo_dir: &Path, inner: &'a mut dyn ServeSink) -> Self {
        Self {
            vault: Arc::clone(vault),
            repo_dir: repo_dir.to_path_buf(),
            inner,
            gating: false,
            carry: Vec::new(),
            phase: AdvertisementPhase::Banner,
            capabilities: None,
            emitted_ref: false,
            projection: None,
            unresolved: false,
        }
    }

    fn drain_carry(&mut self) -> Result<()> {
        while let Some(line) = take_pkt_line(&mut self.carry)? {
            self.handle_line(line)?;
        }
        if self.carry.len() > SERVE_MAX_PKT_LINE_BYTES {
            return Err(serve_failed(
                "git http-backend produced an oversized pkt-line",
            ));
        }
        Ok(())
    }

    fn handle_line(&mut self, line: PktLine) -> Result<()> {
        match (self.phase, line) {
            (AdvertisementPhase::Banner, PktLine::Flush) => {
                self.phase = AdvertisementPhase::Refs;
                self.emit_flush()
            }
            (AdvertisementPhase::Refs, PktLine::Flush) => {
                self.phase = AdvertisementPhase::Trailer;
                self.close_ref_list()
            }
            (AdvertisementPhase::Trailer, PktLine::Flush) => self.emit_flush(),
            (AdvertisementPhase::Refs, PktLine::Data(data)) => self.handle_ref_line(&data),
            (_, PktLine::Data(data)) => self.emit_data(&data),
        }
    }

    /// Ends the ref list, keeping the capability suffix reachable.
    ///
    /// A stock client reads the capabilities off the FIRST ref line, so an
    /// advertisement whose every ref was gated away still has to carry them:
    /// the `capabilities^{}` pseudo-ref is exactly git's own spelling for
    /// "no refs, these capabilities", and it is what an empty repository sends.
    fn close_ref_list(&mut self) -> Result<()> {
        if !self.emitted_ref && self.capabilities.is_some() {
            let mut payload = Vec::new();
            payload.extend_from_slice(ADVERTISED_ZERO_OID.as_bytes());
            payload.push(b' ');
            payload.extend_from_slice(ADVERTISED_CAPABILITIES_REF.as_bytes());
            self.attach_capabilities(&mut payload);
            payload.push(b'\n');
            self.emit_data(&payload)?;
        }
        self.emit_flush()
    }

    fn handle_ref_line(&mut self, line: &[u8]) -> Result<()> {
        let Some((oid, rest)) = split_advertised_ref(line) else {
            return Err(serve_failed(
                "git http-backend produced a malformed advertised ref",
            ));
        };
        let (name, capabilities) = split_capabilities(rest);
        if self.capabilities.is_none() {
            self.capabilities = capabilities.map(<[u8]>::to_vec);
        }
        if !self.keeps_advertised_ref(oid, name) {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(line.len());
        payload.extend_from_slice(oid);
        payload.push(b' ');
        payload.extend_from_slice(name);
        if !self.emitted_ref {
            self.attach_capabilities(&mut payload);
        }
        payload.push(b'\n');
        self.emitted_ref = true;
        self.emit_data(&payload)
    }

    fn attach_capabilities(&self, payload: &mut Vec<u8>) {
        if let Some(capabilities) = self.capabilities.as_ref() {
            payload.push(0);
            let mut first = true;
            for capability in capabilities.split(|byte| *byte == b' ') {
                if let Some(target) = capability.strip_prefix(b"symref=HEAD:") {
                    let visible = self.projection.as_ref().is_some_and(|projection| {
                        projection
                            .published
                            .iter()
                            .any(|(name, _)| name.as_str().as_bytes() == target)
                    });
                    if !visible {
                        continue;
                    }
                }
                if !first {
                    payload.push(b' ');
                }
                payload.extend_from_slice(capability);
                first = false;
            }
        }
    }

    /// Whether one advertised line survives the projection.
    ///
    /// Every "cannot tell" answer is a refusal. Neither an unknown repository
    /// identity nor a missing journal row is evidence of publication.
    fn keeps_advertised_ref(&mut self, oid: &[u8], name: &[u8]) -> bool {
        let (Ok(name), Ok(oid_text)) = (std::str::from_utf8(name), std::str::from_utf8(oid)) else {
            return false;
        };
        if name == ADVERTISED_CAPABILITIES_REF {
            return oid_text == ADVERTISED_ZERO_OID;
        }
        if name.starts_with(GIT_WIRE_KEEP_REF_PREFIX) {
            return false;
        }
        let Ok(value) = GitOid::parse_hex(oid_text) else {
            return false;
        };
        self.ensure_projection(&value);
        let Some(projection) = self.projection.as_ref() else {
            return false;
        };
        if name == "HEAD" {
            return projection.published.iter().any(|(_, oid)| *oid == value);
        }
        // An auxiliary peeled line cannot authorize an object independently
        // of the publication's exact ref/OID pair.
        let base = name.strip_suffix("^{}").unwrap_or(name);
        let Ok(ref_name) = GitRefName::parse_full(base.to_owned()) else {
            return false;
        };
        if !self
            .vault
            .origin_publication_manages_ref(projection.repo_id, &ref_name)
            .unwrap_or(false)
        {
            return false;
        }
        projection
            .published
            .iter()
            .any(|(published, oid)| *published == ref_name && *oid == value)
    }

    fn ensure_projection(&mut self, pin: &GitOid) {
        if self.projection.is_some() || self.unresolved {
            return;
        }
        match resolve_advertisement_projection(&self.vault, &self.repo_dir, pin) {
            Ok(projection) => self.projection = Some(projection),
            Err(_) => self.unresolved = true,
        }
    }

    fn emit_flush(&mut self) -> Result<()> {
        self.inner.write_chunk(b"0000").map_err(Error::Io)
    }

    fn emit_data(&mut self, payload: &[u8]) -> Result<()> {
        let length = payload
            .len()
            .checked_add(4)
            .filter(|length| *length <= SERVE_MAX_PKT_LINE_BYTES)
            .ok_or_else(|| serve_failed("a gated pkt-line does not fit the wire"))?;
        self.inner
            .write_chunk(format!("{length:04x}").as_bytes())
            .map_err(Error::Io)?;
        self.inner.write_chunk(payload).map_err(Error::Io)
    }
}

impl ServeSink for AdvertisedRefGate<'_> {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        self.gating = status == 200 && headers.iter().any(is_advertisement_content_type);
        if !self.gating {
            return self.inner.begin(status, headers);
        }
        // A gated body is shorter than the one the backend measured, so a
        // declared length would be a lie the client waits on forever.
        let framed = headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("Content-Length"))
            .cloned()
            .collect::<Vec<_>>();
        self.inner.begin(status, &framed)
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        if !self.gating {
            return self.inner.write_chunk(bytes);
        }
        self.carry.extend_from_slice(bytes);
        self.drain_carry()
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn is_advertisement_content_type(header: &(String, String)) -> bool {
    header.0.eq_ignore_ascii_case("Content-Type")
        && header.1.starts_with("application/x-git-")
        && header.1.contains("-advertisement")
}

/// Resolves the projection this advertisement is gated against.
fn resolve_advertisement_projection(
    vault: &Vault,
    repo_dir: &Path,
    pin: &GitOid,
) -> Result<AdvertisementProjection> {
    let wire = GitWire::new(vault)?;
    let handle = wire.open_repo(local_repo_ref(repo_dir, pin)?, repo_dir)?;
    let repo_id = lfs_repo_id(&handle.identity().as_hex())?;
    let published = vault.published_origin_refs(&wire, repo_id, &handle)?;
    Ok(AdvertisementProjection { repo_id, published })
}

/// Takes the next complete pkt-line out of `carry`, if one is there.
pub(super) fn take_pkt_line(carry: &mut Vec<u8>) -> Result<Option<PktLine>> {
    if carry.len() < 4 {
        return Ok(None);
    }
    let text = std::str::from_utf8(&carry[..4])
        .map_err(|_| serve_failed("git http-backend produced a non-ASCII pkt-line length"))?;
    let length = usize::from_str_radix(text, 16)
        .map_err(|_| serve_failed("git http-backend produced a non-hex pkt-line length"))?;
    if length == 0 {
        carry.drain(..4);
        return Ok(Some(PktLine::Flush));
    }
    if !(4..=SERVE_MAX_PKT_LINE_BYTES).contains(&length) {
        return Err(serve_failed(
            "git http-backend produced a malformed pkt-line",
        ));
    }
    if carry.len() < length {
        return Ok(None);
    }
    let line = carry[4..length].to_vec();
    carry.drain(..length);
    Ok(Some(PktLine::Data(line)))
}

/// Splits `<oid> <rest>` out of one advertised line, trailing newline removed.
fn split_advertised_ref(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
    let space = trimmed.iter().position(|byte| *byte == b' ')?;
    if space != ADVERTISED_OID_HEX_LEN {
        return None;
    }
    Some((&trimmed[..space], &trimmed[space + 1..]))
}

/// Splits the NUL-delimited capability suffix off an advertised ref line.
fn split_capabilities(rest: &[u8]) -> (&[u8], Option<&[u8]>) {
    match rest.iter().position(|byte| *byte == 0) {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    }
}
