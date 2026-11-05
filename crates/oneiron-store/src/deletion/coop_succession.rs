//! Courtesy asks and answers across a former peer's host re-root (FIX 3014).
//!
//! A pact pins the peer's root key at Connect. When the peer's host
//! re-roots, its old root signs a ReRoot row naming the new one, and the
//! peer's later asks and answers carry the new root's signature. Before
//! each try the sender POSTs the signed ReRoot rows that hand its root on
//! to the key that signed the try, in pages of one body each, to the
//! peer's succession route. The peer keeps the rows that extend the walk
//! from the key it pinned for that pact, and checks the pact's asks and
//! answers against the walk's end. The pinned key never changes, the pact
//! is never reopened, and nothing enters the authority log: the rows are
//! evidence for courtesy alone.
//!
//! Canon is silent on four calls (CALLS `FIX 3014 *`): the rows travel
//! ahead of each try on their own route
//! ([`COOP_DELETION_SUCCESSION_PEER_PATH`]); only a ReRoot row or the host
//! root's own rotation extends the walk ([`succession_edge`]); a key a kept
//! row hands on signs no more courtesy under the pact
//! ([`Vault::courtesy_pact_signer`]); and the pact's pinned key is never
//! re-pinned, ended or not.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::deletion::coop_request::COOP_DELETION_BODY_MAX_BYTES;
use crate::deletion::coop_request::binary;
use crate::deletion::coop_request::decode;
use crate::deletion::coop_request::encode;
use crate::deletion::coop_request::envelope_signature;
use crate::deletion::coop_request::fields;
use crate::deletion::coop_request::invalid;
use crate::deletion::coop_request::peek_cooperative_deletion_pact;
use crate::deletion::coop_request::uint;
use oneiron_authority::authority::{
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityVaultId, DeviceAuthority,
    FederationPactState, ROLE_OWNER, authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron_base::error::Result;
use oneiron_contracts::authority::AuthorityEntryHash;

/// The peer route a succession page is POSTed to, ahead of each try of an
/// ask or an answer (FIX 3014, a call: the rows travel on their own route,
/// so the signed ask and answer keep their bytes).
pub const COOP_DELETION_SUCCESSION_PEER_PATH: &str = "/v1/federation/courtesy-delete/succession";
/// Wire schema version of a succession page.
pub const COOP_DELETION_SUCCESSION_SCHEMA_VERSION: u64 = 1;
/// Exact canonical page keys, in wire order.
const PAGE_KEYS: [&str; 3] = ["schema_version", "pact_id", "entries"];

/// Which signed row extends a courtesy succession walk (FIX 3014, FIX 3798,
/// a call): a ReRoot naming an Owner-role successor other than its signer,
/// or the host root's own RotateKey, signed by the old key it rotates, naming
/// one. An enrolment, an Admin or Owner device add, a rotation another key
/// signed and every other op extend nothing, whatever the peer's roster
/// makes of them.
pub fn succession_edge(entry: &AuthorityLogEntry) -> Option<&DeviceAuthority> {
    match &entry.op {
        AuthorityOp::ReRoot { new_device }
            if new_device.roles & ROLE_OWNER != 0 && new_device.key != entry.signer.public_key =>
        {
            Some(new_device)
        }
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } if *old_key == entry.signer.public_key
            && new_device.roles & ROLE_OWNER != 0
            && new_device.key != *old_key =>
        {
            Some(new_device)
        }
        _ => None,
    }
}

/// A walk from a pact's pinned key over its peer's succession rows.
pub struct Walk {
    /// The key the last row on the walk hands on to: the pinned key when none does.
    pub end: AuthorityKey,
    /// The rows on the walk, in walk order, by hash.
    pub rows: Vec<(AuthorityEntryHash, Vec<u8>)>,
}

/// One page: the pact and its rows, in the courtesy codec.
fn encode_page(pact_id: &[u8; 32], rows: &[Vec<u8>]) -> Result<Vec<u8>> {
    let values = [
        Value::from(COOP_DELETION_SUCCESSION_SCHEMA_VERSION),
        Value::Binary(pact_id.to_vec()),
        Value::Array(rows.iter().map(|row| Value::Binary(row.clone())).collect()),
    ];
    encode(&Value::Map(
        PAGE_KEYS
            .iter()
            .zip(values)
            .map(|(key, value)| (Value::from(*key), value))
            .collect(),
    ))
}

/// Reads one canonical page: exact keys, at least one row, no alternate spelling.
pub fn decode_page(bytes: &[u8]) -> Result<([u8; 32], Vec<Vec<u8>>)> {
    let value = decode(bytes)?;
    let f = fields(&value, &PAGE_KEYS)?;
    if uint(f[0])? != COOP_DELETION_SUCCESSION_SCHEMA_VERSION {
        return Err(invalid());
    }
    let pact_id = binary::<32>(f[1])?;
    let rows = f[2]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|row| match row {
            Value::Binary(row) => Ok(row.clone()),
            _ => Err(invalid()),
        })
        .collect::<Result<Vec<_>>>()?;
    if rows.is_empty() || encode_page(&pact_id, &rows)? != bytes {
        return Err(invalid());
    }
    Ok((pact_id, rows))
}

/// Splits `rows` into pages, in order, each one body the peer's route takes
/// ([`COOP_DELETION_BODY_MAX_BYTES`]). No row is dropped: a longer chain is
/// more pages, never a bigger one (Rule 5).
pub fn pages(pact_id: &[u8; 32], rows: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    let mut pages = Vec::new();
    let mut page: Vec<Vec<u8>> = Vec::new();
    for row in rows {
        page.push(row);
        if page.len() > 1 && encode_page(pact_id, &page)?.len() > COOP_DELETION_BODY_MAX_BYTES {
            let spill: Vec<Vec<u8>> = page.pop().into_iter().collect();
            pages.push(encode_page(pact_id, &page)?);
            page = spill;
        }
    }
    if !page.is_empty() {
        pages.push(encode_page(pact_id, &page)?);
    }
    Ok(pages)
}

/// The succession a claimed try rides behind (FIX 3014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionSuccession {
    /// The peer's succession route, on the try's own origin.
    pub destination: String,
    /// The pages in chain order, each one body. All of them go, in order,
    /// before the try's own bytes.
    pub pages: Vec<Vec<u8>>,
}
