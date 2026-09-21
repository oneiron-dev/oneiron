//! Explicit owner-controlled origin epochs. No expiry, automatic failover or mirror writes.
use super::publication::{
    OriginPublicationReceipt, OriginPublicationRequest, origin_publication_id,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, GitWireRepo, lock_repository};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::path::Path;

const PREFIX: &[u8] = b"origin:authority:v1:";
const PERMIT: &[u8] = b"origin:authority_permit:v1:";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginResidence {
    LocalVault,
    CloudVault,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    repo_id: EntityId,
    epoch: u64,
    writer: String,
}
/// Persisted host authorization. This is deliberately not a public deserializer
/// for `OriginAuthorityLease`: only local admission evidence can restore it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::origin) struct OriginAuthorityStamp {
    repo_id: String,
    epoch: u64,
    writer: String,
}
impl OriginAuthorityStamp {
    pub(in crate::origin) fn from_lease(lease: &OriginAuthorityLease) -> Self {
        Self {
            repo_id: lease.repo_id.to_hex(),
            epoch: lease.epoch,
            writer: lease.writer.clone(),
        }
    }
    pub(in crate::origin) fn lease(&self) -> Result<OriginAuthorityLease> {
        Ok(OriginAuthorityLease {
            repo_id: EntityId::from_hex(&self.repo_id)?,
            epoch: self.epoch,
            writer: self.writer.clone(),
        })
    }
    pub(in crate::origin) fn evidence_value(stamp: Option<&Self>) -> Value {
        stamp.map_or(Value::Nil, |stamp| {
            Value::Array(vec![
                Value::from(stamp.repo_id.clone()),
                Value::from(stamp.epoch),
                Value::from(stamp.writer.clone()),
            ])
        })
    }
    pub(in crate::origin) fn from_evidence(value: &Value) -> Result<Option<Self>> {
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
        EntityId::from_hex(&writer).map_err(|_| invalid())?;
        Ok(Some(Self {
            repo_id: repo_id.to_hex(),
            epoch,
            writer,
        }))
    }
}
fn key(repo: EntityId) -> Vec<u8> {
    [PREFIX, repo.as_bytes()].concat()
}
fn permit(id: EntityId) -> Vec<u8> {
    [PERMIT, id.as_bytes()].concat()
}
fn decode(raw: &[u8]) -> Result<OriginAuthority> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("origin authority row"))
}
impl Vault {
    pub fn origin_authority(&self, repo: &GitWireRepo) -> Result<Option<OriginAuthority>> {
        let id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        self.origin_authority_by_id(id)
    }
    fn origin_authority_by_id(&self, id: EntityId) -> Result<Option<OriginAuthority>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(id))?
            .map(|raw| decode(&raw))
            .transpose()
    }
    /// Trusted owner administration. This explicit CAS is the only epoch cutover.
    /// The caller must finish the census before handing authority to another host.
    pub fn set_origin_authority(
        &self,
        repo: &GitWireRepo,
        expected_epoch: Option<u64>,
        residence: OriginResidence,
        writer: EntityId,
        mirror: bool,
    ) -> Result<OriginAuthority> {
        let _guard = lock_repository(repo.common_dir())?;
        let id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        self.reconcile_receive_pack_operations(repo.repo_root())?;
        if self.has_pending_receive_pack_operations(repo.repo_root())?
            || self.prepared_origin_publication_count(id)? != 0
        {
            return Err(Error::ConcurrentWrite(
                "origin cutover requires a drained publication census",
            ));
        }
        let mut txn = self.store.env.write_txn()?;
        let current = self
            .store
            .vault_meta
            .get(&txn, &key(id))?
            .map(|raw| decode(&raw))
            .transpose()?;
        if current.as_ref().map(|row| row.epoch) != expected_epoch {
            return Err(Error::ConcurrentWrite("origin authority epoch moved"));
        }
        let row = OriginAuthority {
            epoch: expected_epoch
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("origin epoch"))?,
            residence,
            writer: writer.to_hex(),
            mirror,
        };
        let bytes = rmp_serde::to_vec_named(&row)
            .map_err(|_| Error::InvariantViolation("origin authority encoding"))?;
        self.store.vault_meta.put(&mut txn, &key(id), &bytes)?;
        txn.commit()?;
        Ok(row)
    }
    /// Host authorization is separate from the pusher's actor attribution.
    pub fn lease_origin_authority(
        &self,
        repo: &GitWireRepo,
        writer: EntityId,
    ) -> Result<OriginAuthorityLease> {
        let row = self.origin_authority(repo)?.ok_or(Error::EntityNotFound)?;
        if row.mirror || row.writer != writer.to_hex() {
            return Err(Error::InvariantViolation(
                "origin is read-only or another host owns authority",
            ));
        }
        Ok(OriginAuthorityLease {
            repo_id: crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?,
            epoch: row.epoch,
            writer: row.writer,
        })
    }
    pub fn publish_origin_ref_authorized(
        &self,
        git: &GitWire<'_>,
        request: OriginPublicationRequest,
        lease: &OriginAuthorityLease,
    ) -> Result<OriginPublicationReceipt> {
        let _guard = lock_repository(request.repo.common_dir())?;
        let current = self
            .origin_authority(&request.repo)?
            .ok_or(Error::EntityNotFound)?;
        if request.repo_id != lease.repo_id
            || current.epoch != lease.epoch
            || current.writer != lease.writer
            || current.mirror
        {
            return Err(Error::ConcurrentWrite("stale origin authority lease"));
        }
        let id = origin_publication_id(&request)?;
        self.with_write_txn(|txn| {
            // A publication decided in an earlier epoch cannot be reauthorized.
            if let Some(raw) = self.store.vault_meta.get(txn, &permit(id))? {
                if raw.as_ref() != lease.epoch.to_be_bytes() {
                    return Err(Error::ConcurrentWrite(
                        "publication belongs to a previous authority epoch",
                    ));
                }
            } else {
                self.store
                    .vault_meta
                    .put(txn, &permit(id), &lease.epoch.to_be_bytes())?;
            }
            Ok(())
        })?;
        self.publish_origin_ref(git, request)
    }
    pub(in crate::origin) fn require_origin_authority(
        &self,
        repo: &GitWireRepo,
        publication: EntityId,
    ) -> Result<()> {
        let Some(row) = self.origin_authority(repo)? else {
            return Ok(());
        };
        if row.mirror {
            return Err(Error::InvariantViolation(
                "mirror is read-only; import through the authoritative origin",
            ));
        }
        let txn = self.store.env.read_txn()?;
        if self
            .store
            .vault_meta
            .get(&txn, &permit(publication))?
            .is_none_or(|raw| raw.as_ref() != row.epoch.to_be_bytes())
        {
            return Err(Error::ConcurrentWrite(
                "origin publication requires the current authority epoch",
            ));
        }
        Ok(())
    }
    /// Admission has no commit pin yet, including an empty first-push origin.
    /// Resolve the canonical object-store identity without inventing a commit.
    pub(in crate::origin) fn require_receive_pack_host_at(
        &self,
        repo_root: &Path,
        authority: Option<&OriginAuthorityStamp>,
    ) -> Result<()> {
        let wire = GitWire::new(self)?;
        let identity = wire.repository_identity(repo_root)?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&identity.as_hex())?;
        self.require_receive_pack_host(repo_id, authority)
    }

    pub(in crate::origin) fn require_receive_pack_host(
        &self,
        repo_id: EntityId,
        authority: Option<&OriginAuthorityStamp>,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        self.require_receive_pack_host_in_txn(&txn, repo_id, authority)
    }
    pub(in crate::origin) fn require_receive_pack_host_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo_id: EntityId,
        authority: Option<&OriginAuthorityStamp>,
    ) -> Result<()> {
        let row = self
            .store
            .vault_meta
            .get(txn, &key(repo_id))?
            .map(|raw| decode(&raw))
            .transpose()?;
        match (row, authority) {
            (None, None) => Ok(()),
            (Some(row), Some(stamp))
                if !row.mirror
                    && stamp.repo_id == repo_id.to_hex()
                    && row.epoch == stamp.epoch
                    && row.writer == stamp.writer =>
            {
                Ok(())
            }
            _ => Err(Error::ConcurrentWrite(
                "receive-pack requires the current origin host authority",
            )),
        }
    }
}
