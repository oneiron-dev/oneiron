//! A vault VM's custody anchor channels (FIX 6517): the owner credential a
//! custody anchor door admits, carried into a Firecracker guest, and the one
//! route by which the guest reaches that door.
//!
//! - The exchange, [`VM_ANCHOR_PORT`](crate::vm::VM_ANCHOR_PORT). The
//!   guest's root bootstrap dials it once on every cold boot that serves,
//!   after its provision connection and before it starts the engine, and the
//!   host sends the [`VmAnchorHeader`] at once: the anchor URL it bound the
//!   boot to, exactly as configured, and whether a credential follows. Only
//!   after the engine's credential frame does the host send the payload: a
//!   big-endian u32 length, then exactly the native credential's bytes (the
//!   object a node's engine reads on `--custody-anchor-credentials-fd`), or
//!   a length of zero when there is none, then a half-close. The bootstrap
//!   hands those bytes to the engine on an ordinary pipe, which the engine
//!   reads with its native reader, and answers one [`VmAnchorReply`]. The
//!   reply says the bytes crossed, never that the vault is ready or that its
//!   anchor answered. No credential is no refusal: the anchor stays pending.
//! - The proxy, [`VM_ANCHOR_PROXY_PORT`](crate::vm::VM_ANCHOR_PROXY_PORT).
//!   The bootstrap serves a socket of the engine's own,
//!   [`VM_GUEST_ANCHOR_SOCKET`], when the host bound a URL. Each stream on
//!   it dials the proxy port and says [`VmAnchorProxyHello`]; the host
//!   answers [`VmAnchorProxyReply`] and, once accepted, carries the stream's
//!   bytes to the bound URL's host and port, and to nothing else. The guest
//!   names no destination, and nothing on the way adds a credential or reads
//!   what passes. The engine's door client takes this socket for exactly the
//!   bound URL; the URL itself, its TLS and its host checks are unchanged.
//!
//! Every record but the payload is a big-endian u32 length, then that many
//! bytes of one JSON object. The bounds here are the channels' codec only:
//! a node's credential has none.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The exchange's wire revision. An image manifest names it as
/// `anchor_wire_revision`, beside `anchor_proxy_revision`; a host delivers a
/// credential only to an image that names both.
pub const VM_ANCHOR_WIRE_REVISION: u32 = 1;
/// The proxy's wire revision, `anchor_proxy_revision` in an image manifest.
pub const VM_ANCHOR_PROXY_REVISION: u32 = 1;
/// The longest exchange record's JSON: a header or a reply.
pub const MAX_VM_ANCHOR_RECORD_BYTES: usize = crate::MAX_CTL_LINE;
/// The longest credential the exchange carries.
pub const MAX_VM_ANCHOR_CREDENTIAL_BYTES: usize = crate::MAX_CTL_LINE;
/// The longest proxy record's JSON: a hello or a reply.
pub const MAX_VM_ANCHOR_PROXY_RECORD_BYTES: usize = crate::vm::MAX_VM_FRAME;
/// The guest socket that reaches the bound anchor URL: owned by the vault's
/// UID, mode 0600, on the guest's `/run` tmpfs.
pub const VM_GUEST_ANCHOR_SOCKET: &str = "/run/oneiron/custody-anchor.sock";

/// The host's first record on the exchange. `anchor_url` is `null` when the
/// host bound none, and a credential follows only with a URL.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmAnchorHeader {
    pub revision: u32,
    /// The vault the host's boot names.
    pub vault: String,
    /// The anchor URL the boot is bound to, byte for byte as the vault's
    /// effective settings name it, a restore's plan included.
    #[serde(deserialize_with = "Option::deserialize")]
    pub anchor_url: Option<String>,
    pub has_credentials: bool,
}

impl fmt::Debug for VmAnchorHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmAnchorHeader")
            .field("revision", &self.revision)
            .field("vault", &self.vault)
            .field("anchor_url", &self.anchor_url.as_ref().map(|_| "<bound>"))
            .field("has_credentials", &self.has_credentials)
            .finish()
    }
}

impl VmAnchorHeader {
    /// Refuses a header this end cannot take for `vault`'s boot: another
    /// revision, another vault, or a credential with no URL to bind it to.
    pub fn check(&self, vault: &str) -> Result<(), VmAnchorRefusal> {
        if self.revision != VM_ANCHOR_WIRE_REVISION {
            return Err(VmAnchorRefusal::RevisionUnsupported);
        }
        if self.vault != vault {
            return Err(VmAnchorRefusal::VaultMismatch);
        }
        match &self.anchor_url {
            Some(url) if url.is_empty() => Err(VmAnchorRefusal::HeaderInvalid),
            None if self.has_credentials => Err(VmAnchorRefusal::HeaderInvalid),
            _ => Ok(()),
        }
    }
}

/// The guest's answer on the exchange, after the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum VmAnchorReply {
    /// The payload crossed whole. `anchor_identity_digest` is the bound
    /// URL's ([`anchor_identity_digest`]), `null` when the host bound none.
    Accepted {
        revision: u32,
        vault: String,
        #[serde(deserialize_with = "Option::deserialize")]
        anchor_identity_digest: Option<String>,
    },
    /// The header or the payload was refused.
    Refused { code: VmAnchorRefusal },
}

/// Why the exchange was refused, in closed names: never a URL, a byte of a
/// credential or an error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmAnchorRefusal {
    /// The header's revision is not the exchange's.
    RevisionUnsupported,
    /// The header names another vault than the boot's.
    VaultMismatch,
    /// The header is not one header, or names a credential without a URL.
    HeaderInvalid,
    /// The payload's length, its bytes or the end after them is not one
    /// payload, or it carries a credential the header did not announce.
    PayloadInvalid,
}

/// A guest stream's first record on the proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmAnchorProxyHello {
    pub revision: u32,
    pub vault: String,
    /// The URL the guest's header bound ([`anchor_identity_digest`]).
    pub anchor_identity_digest: String,
}

/// The host's answer to a proxy hello. After `accepted` the stream carries
/// the bound origin's bytes both ways; after `refused` it ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum VmAnchorProxyReply {
    Accepted { revision: u32 },
    Refused { code: VmAnchorProxyRefusal },
}

/// Why a proxy stream was refused, in closed names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmAnchorProxyRefusal {
    /// The hello's revision is not the proxy's.
    RevisionUnsupported,
    /// The hello names another vault than the boot's.
    VaultMismatch,
    /// The hello is not one hello.
    HelloInvalid,
    /// The hello's digest is not the bound URL's.
    IdentityMismatch,
    /// The host bound no anchor URL to this boot.
    NoAnchor,
    /// The host did not reach the bound URL's host and port.
    Unreachable,
}

/// The digest that names an anchor URL on the wire: the BLAKE3 of its exact
/// UTF-8 bytes, in lowercase hex.
#[must_use]
pub fn anchor_identity_digest(url: &str) -> String {
    crate::hex(blake3::hash(url.as_bytes()).as_bytes())
}

/// One record: its length prefix, then `record` as JSON, refused over `cap`.
pub fn encode_vm_anchor_record(record: &impl Serialize, cap: usize) -> anyhow::Result<Vec<u8>> {
    let body = serde_json::to_vec(record)?;
    anyhow::ensure!(body.len() <= cap, "vm anchor record over its cap");
    let mut bytes = u32::try_from(body.len())?.to_be_bytes().to_vec();
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// A record's body length from its prefix: refused when empty or over `cap`,
/// before any of the body is read.
pub fn vm_anchor_record_len(prefix: [u8; 4], cap: usize) -> anyhow::Result<usize> {
    let len = usize::try_from(u32::from_be_bytes(prefix))?;
    anyhow::ensure!((1..=cap).contains(&len), "vm anchor record of {len} bytes");
    Ok(len)
}

/// Parses one record's body. The parser's own message could quote what it
/// read, so a refusal says only that it is not one record.
pub fn decode_vm_anchor_record<T: DeserializeOwned>(body: &[u8]) -> anyhow::Result<T> {
    serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("not one vm anchor record"))
}

/// Reads one whole record from a blocking reader.
pub fn read_vm_anchor_record<T: DeserializeOwned>(
    reader: &mut impl std::io::Read,
    cap: usize,
) -> anyhow::Result<T> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix)?;
    let mut body = vec![0u8; vm_anchor_record_len(prefix, cap)?];
    reader.read_exact(&mut body)?;
    decode_vm_anchor_record(&body)
}

/// The payload's prefix for a credential of `len` bytes; zero is none.
pub fn vm_anchor_payload_prefix(len: usize) -> anyhow::Result<[u8; 4]> {
    anyhow::ensure!(
        len <= MAX_VM_ANCHOR_CREDENTIAL_BYTES,
        "the custody anchor credential is over the VM exchange's {MAX_VM_ANCHOR_CREDENTIAL_BYTES} bytes"
    );
    Ok(u32::try_from(len)?.to_be_bytes())
}

/// A payload's credential length from its prefix, refused over the cap
/// before any of it is read.
pub fn vm_anchor_payload_len(prefix: [u8; 4]) -> Result<usize, VmAnchorRefusal> {
    usize::try_from(u32::from_be_bytes(prefix))
        .ok()
        .filter(|len| *len <= MAX_VM_ANCHOR_CREDENTIAL_BYTES)
        .ok_or(VmAnchorRefusal::PayloadInvalid)
}
