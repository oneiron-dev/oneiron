//! Explicit owner-controlled origin epochs. No expiry, automatic failover or mirror writes.
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use crate::origin::publication::publication_codec::origin_publication_id;
use crate::origin::publication::publication_types::OriginPublicationReceipt;
use crate::origin::publication::publication_types::OriginPublicationRequest;
use crate::receipt_identity::ERASED_CALL_IDENTITY;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// The writer an erased host leaves in the authority row, its admission
/// stamps and its intents (FIX 3877; a call, L02's ruling): one fixed marker,
/// never Nil and never a dropped field, so it can never read as an
/// unconfigured origin. The repository and epoch stay; no host holds the
/// repository until the owner's explicit cutover, and nothing fails over.
pub const ORIGIN_ERASED_WRITER: &str = ERASED_CALL_IDENTITY;
/// What a write against an origin whose writer was erased is told (FIX 5024;
/// a call): it names the owner's cutover, never another host. A live writer
/// elsewhere keeps its own refusal.
pub const ORIGIN_WRITER_ERASED_REFUSAL: &str = "this origin's writer was erased; it takes no write until the owner's cutover names its next writer";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OriginResidence {
    LocalVault,
    CloudVault,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginAuthority {
    pub epoch: u64,
    pub residence: OriginResidence,
    /// The one host/vault principal that can obtain an epoch-bound publication permit.
    pub writer: String,
    /// Mirrored repositories are read-only, including main and deletions.
    pub mirror: bool,
}
#[derive(Debug, Clone)]
pub struct OriginAuthorityLease {
    pub repo_id: EntityId,
    pub epoch: u64,
    pub writer: String,
}
impl OriginAuthorityLease {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
/// What one host holds of a served repository's origin authority, read from
/// trusted host configuration and the authority row, never from the pusher.
#[derive(Debug, Clone)]
pub enum OriginHostAuthority {
    /// No authority is configured: this vault is the repository's one origin
    /// and serves its pushes with no lease.
    Unconfigured,
    /// This host writes the current epoch.
    Held(OriginAuthorityLease),
    /// The repository is a read-only mirror at the current epoch.
    Mirror(OriginAuthority),
    /// Another host writes the current epoch, or this host names none.
    Elsewhere(OriginAuthority),
    /// An erase took the current epoch's writer (FIX 3877): no host writes
    /// the repository until the owner's cutover names one (FIX 5024).
    WriterErased(OriginAuthority),
}
/// Persisted host authorization. This is deliberately not a public deserializer
/// for `OriginAuthorityLease`: only local admission evidence can restore it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginAuthorityStamp {
    pub repo_id: String,
    pub epoch: u64,
    pub writer: String,
}
impl OriginAuthorityStamp {
    pub fn from_lease(lease: &OriginAuthorityLease) -> Self {
        Self {
            repo_id: lease.repo_id.to_hex(),
            epoch: lease.epoch,
            writer: lease.writer.clone(),
        }
    }
    pub fn lease(&self) -> Result<OriginAuthorityLease> {
        if self.writer_erased() {
            return Err(Error::ConcurrentWrite(
                "an erased origin host holds no lease",
            ));
        }
        Ok(OriginAuthorityLease {
            repo_id: EntityId::from_hex(&self.repo_id)?,
            epoch: self.epoch,
            writer: self.writer.clone(),
        })
    }
    pub fn evidence_value(stamp: Option<&Self>) -> Value {
        stamp.map_or(Value::Nil, |stamp| {
            Value::Array(vec![
                Value::from(stamp.repo_id.clone()),
                Value::from(stamp.epoch),
                Value::from(stamp.writer.clone()),
            ])
        })
    }
    pub fn from_evidence(value: &Value) -> Result<Option<Self>> {
        if value.is_nil() {
            return Ok(None);
        }
        let invalid = || Error::CorruptedIndex("receive-pack origin authority");
        let fields = value
            .as_array()
            .filter(|fields| fields.len() == 3)
            .ok_or_else(invalid)?;
        let repo_id =
            EntityId::from_hex(fields[0].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let epoch = fields[1]
            .as_u64()
            .filter(|epoch| *epoch != 0)
            .ok_or_else(invalid)?;
        let writer = fields[2].as_str().ok_or_else(invalid)?.to_owned();
        // An erased host is its own state, never an absent stamp.
        if writer != ORIGIN_ERASED_WRITER {
            EntityId::from_hex(&writer).map_err(|_| invalid())?;
        }
        Ok(Some(Self {
            repo_id: repo_id.to_hex(),
            epoch,
            writer,
        }))
    }
    /// Whether an erase took the host this stamp names.
    pub fn writer_erased(&self) -> bool {
        self.writer == ORIGIN_ERASED_WRITER
    }
    /// Names [`ORIGIN_ERASED_WRITER`] where the stamp names `actor`; `true`
    /// when it did.
    pub fn erase_writer(&mut self, actor: &EntityId) -> bool {
        let named = self.writer == actor.to_hex();
        if named {
            ORIGIN_ERASED_WRITER.clone_into(&mut self.writer);
        }
        named
    }
}
