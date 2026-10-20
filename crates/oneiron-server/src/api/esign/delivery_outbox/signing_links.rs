//! The signing link an invitation or reminder envelope carries (FIX 5238
//! option 3): its base, its export-only form, the digest of the content an
//! envelope delivers with it, and the reuse of an envelope already written
//! for the current lease.
//!
//! The link exists raw only in the envelope this writer exports and in the
//! sender that reads it: never in the queue's payloads, the vault, the
//! dispatch ledger, a receipt, an ack or a log line. The vault keeps the
//! link's digest and the delivered-content digest beside the lease.

use oneiron::attempt_queue::AttemptRecord;
use oneiron::blob_artifact::esign::EsignCapability;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};

use super::wire::hex;
use super::{LEASE_OWNER, SCHEMA_VERSION};

/// The signing page a link opens; the capability rides its fragment, never
/// its path or query.
const SIGN_PAGE_PATH: &str = "/sign";

/// One envelope's signing link: the URL the recipient opens and when it
/// stops working. No `Debug`: the URL holds a live capability.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SigningLink {
    url: String,
    hard_expires_at: u64,
}

impl SigningLink {
    pub(super) fn new(base: &str, capability: &EsignCapability, hard_expires_at: u64) -> Self {
        Self {
            url: format!(
                "{base}{SIGN_PAGE_PATH}#{}",
                capability.expose_for_delivery()
            ),
            hard_expires_at,
        }
    }
}

/// The public https base links are built on: `oauth_resource_indicator`
/// (`--oauth-resource-indicator`), parsed whole, without its trailing
/// slash. With none, or one that is not an https base URL, invitations and
/// reminders are held unexported with this reason; no Host header, bind
/// address or localhost stands in for it.
pub(super) fn signing_base(configured: Option<&str>) -> Result<String, &'static str> {
    let Some(configured) = configured.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(
            "no public signing base: set oauth_resource_indicator (--oauth-resource-indicator) to the host's https origin",
        );
    };
    let url = reqwest::Url::parse(configured)
        .map_err(|_| "oauth_resource_indicator is not a URL, so no signing link can name it")?;
    let base = url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !url.cannot_be_a_base();
    if !base {
        return Err(
            "oauth_resource_indicator is not an https base URL, so no signing link can name it",
        );
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// The digest of what one envelope delivers, which its ack echoes as
/// `payload_sha256`: the queued notice's bytes as the file holds them and,
/// for an invitation or reminder, a NUL, the link's URL, a NUL and its
/// `hard_expires_at` as 8 big-endian bytes. A notice with no link digests
/// its bytes alone.
pub(super) fn delivered_digest(payload: &RawValue, link: Option<&SigningLink>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload.get().as_bytes());
    if let Some(link) = link {
        hasher.update([0]);
        hasher.update(link.url.as_bytes());
        hasher.update([0]);
        hasher.update(link.hard_expires_at.to_be_bytes());
    }
    hasher.finalize().into()
}

/// The members of a written envelope its reuse reads.
#[derive(Deserialize)]
struct Written<'a> {
    schema_version: u32,
    attempt_id: String,
    lease_owner: String,
    attempt_count: u32,
    payload_sha256: String,
    #[serde(borrow)]
    payload: &'a RawValue,
    signing_link: Option<SigningLink>,
}

/// Whether `bytes`, the envelope on disk, is this lease's whole and valid:
/// it names `row`'s current lease, carries a link, and its content digests
/// to `delivered`, the digest the vault recorded when it minted that link.
/// Such an envelope is kept as it is, and no second link is minted for it.
pub(super) fn holds_lease(bytes: &[u8], row: &AttemptRecord, delivered: &str) -> bool {
    let Ok(written) = serde_json::from_slice::<Written<'_>>(bytes) else {
        return false;
    };
    written.schema_version == SCHEMA_VERSION
        && written.attempt_id == hex(row.id.as_bytes())
        && written.lease_owner == LEASE_OWNER
        && written.attempt_count == row.attempt_count
        && written.payload_sha256 == delivered
        && written
            .signing_link
            .as_ref()
            .is_some_and(|link| hex(&delivered_digest(written.payload, Some(link))) == delivered)
}
