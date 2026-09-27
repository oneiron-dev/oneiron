//! Node-local Gmail mailbox progress, keyed by delegated identity.
//!
//! A page cursor belongs to one mailbox AND one placement policy. A policy
//! change starts a fresh scan, never hands an old provider token to a widened
//! read. Failed page admission leaves the stored progress untouched.

use serde::{Deserialize, Serialize};

use super::mail_placement::PlacementPolicy;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const MAILBOX_CURSOR_PREFIX: &[u8] = b"gmail:mailbox_cursor:v1:";
const MAX_CURSOR_BYTES: usize = 256;

/// Provider-opaque, bounded page token. Never a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MailboxPageToken(String);

impl MailboxPageToken {
    /// Admit one provider token at the boundary.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a blank or overlong token.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_mailbox_cursor(&value)?;
        Ok(Self(value))
    }

    /// The opaque value to hand back to the host provider wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Persisted progress for one delegated identity's mailbox read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxCursor {
    /// Normalized mailbox address of the identity this cursor belongs to.
    pub mailbox_address: String,
    /// Changing placement invalidates the prior provider cursor.
    pub placement_policy: PlacementPolicy,
    /// Opaque provider page token, never a credential.
    pub next_cursor: Option<MailboxPageToken>,
    /// Number of fully admitted pages in this policy's scan.
    pub pages_completed: u64,
    /// Completion time of the most recent full scan (not an intermediate page).
    pub last_complete_at: Option<u64>,
}

impl MailboxCursor {
    /// Empty progress for a fresh scan.
    #[must_use]
    pub fn new(mailbox_address: impl Into<String>, placement_policy: PlacementPolicy) -> Self {
        Self {
            mailbox_address: mailbox_address.into(),
            placement_policy,
            next_cursor: None,
            pages_completed: 0,
            last_complete_at: None,
        }
    }

    /// The cursor to use for this binding. Any change of mailbox or policy
    /// restarts the scan; a stale worker cannot subsequently commit its page.
    #[must_use]
    pub fn for_binding(self, mailbox_address: &str, policy: PlacementPolicy) -> Self {
        if self.mailbox_address == mailbox_address && self.placement_policy == policy {
            self
        } else {
            Self::new(mailbox_address, policy)
        }
    }
}

/// Reject malformed provider tokens on both sides of the wire, including
/// stored state that might otherwise be sent back to a provider.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a blank or overlong token.
pub fn validate_mailbox_cursor(cursor: &str) -> Result<()> {
    if cursor.trim().is_empty() || cursor.len() > MAX_CURSOR_BYTES {
        return Err(Error::InvalidConfig(
            "gmail page cursor must be non-empty and at most 256 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn cursor_key(identity_id: EntityId) -> Vec<u8> {
    let mut key = MAILBOX_CURSOR_PREFIX.to_vec();
    key.extend_from_slice(identity_id.to_hex().as_bytes());
    key
}

/// Host-visible progress snapshot. The absence of a row means no page has
/// been admitted for this delegated identity yet.
///
/// # Errors
///
/// Store failure or malformed stored progress (never treated as a fresh scan).
pub fn mailbox_cursor_snapshot(
    vault: &Vault,
    identity_id: EntityId,
) -> Result<Option<MailboxCursor>> {
    let txn = vault.store.env.read_txn()?;
    decode_cursor(vault.store.vault_meta.get(&txn, &cursor_key(identity_id))?)
}

fn decode_cursor(raw: Option<std::borrow::Cow<'_, [u8]>>) -> Result<Option<MailboxCursor>> {
    raw.map(|bytes| {
        let row: MailboxCursor = serde_json::from_slice(bytes.as_ref()).map_err(|_| {
            Error::InvalidConfig("gmail mailbox cursor row did not decode".to_owned())
        })?;
        if let Some(cursor) = &row.next_cursor {
            validate_mailbox_cursor(cursor.as_str())?;
        }
        Ok(row)
    })
    .transpose()
}

/// Advance only if storage still matches the state read before the fetch.
/// Replaying an admitted page is safe, but two competing workers may not
/// overwrite one another's progress or revert a changed placement policy.
///
/// # Errors
///
/// Store, encode, malformed token, or concurrent-progress failure.
pub(super) fn advance_mailbox_cursor(
    vault: &Vault,
    identity_id: EntityId,
    previous: Option<&MailboxCursor>,
    next: &MailboxCursor,
) -> Result<()> {
    if let Some(cursor) = &next.next_cursor {
        validate_mailbox_cursor(cursor.as_str())?;
    }
    let key = cursor_key(identity_id);
    let encoded = serde_json::to_vec(next)
        .map_err(|_| Error::InvalidConfig("gmail mailbox cursor did not encode".to_owned()))?;
    vault.try_with_write_txn(|txn| {
        let current = decode_cursor(vault.store.vault_meta.get(txn, &key)?)?;
        if current.as_ref() != previous {
            return Err(Error::InvalidConfig(
                "gmail mailbox cursor changed during page read".to_owned(),
            ));
        }
        vault.store.vault_meta.put(txn, &key, &encoded)?;
        Ok(())
    })
}
