//! Explicit owner-controlled origin epochs. No expiry, automatic failover or mirror writes.
use super::publication::{
    OriginPublicationReceipt, OriginPublicationRequest, origin_publication_id,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, GitWireRepo, lock_repository};
use crate::side_table::{self, Named, Raw, SideTable};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Owner-controlled origin residence/epoch/writer authority for one repository. Key: repo id.
const AUTHORITY: SideTable<EntityId, OriginAuthority, Named> =
    SideTable::new(&side_table::ORIGIN_AUTHORITY);

/// Epoch-bound publication permit stamp (u64be epoch), authorizing one publication under the
/// current authority epoch. Key: publication id.
const AUTHORITY_PERMIT: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::ORIGIN_AUTHORITY_PERMIT);
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
    repo_id: EntityId,
    epoch: u64,
    writer: String,
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
}
/// The owner's cutover: the epoch it expects and the authority it installs.
struct Cutover {
    expected_epoch: Option<u64>,
    residence: OriginResidence,
    writer: EntityId,
    mirror: bool,
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
impl Vault {
    pub fn origin_authority(&self, repo: &GitWireRepo) -> Result<Option<OriginAuthority>> {
        let id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        self.origin_authority_by_id(id)
    }
    fn origin_authority_by_id(&self, id: EntityId) -> Result<Option<OriginAuthority>> {
        let txn = self.store.env.read_txn()?;
        AUTHORITY.get(&self.store, &txn, &id)
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
        let id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        let cutover = Cutover {
            expected_epoch,
            residence,
            writer,
            mirror,
        };
        self.cut_origin_authority(repo.common_dir(), repo.repo_root(), id, cutover)
    }
    /// [`Vault::set_origin_authority`] for a repository this vault serves,
    /// named as its smart-HTTP route names it: the owner's cutover on the
    /// host itself. It takes the coordinator a push to that name takes.
    pub fn set_served_origin_authority(
        &self,
        repo_name: &str,
        expected_epoch: Option<u64>,
        residence: OriginResidence,
        writer: EntityId,
        mirror: bool,
    ) -> Result<OriginAuthority> {
        let repo_root = super::smart_http::origin_repo_dir(self, repo_name)?;
        let common_dir = super::smart_http::push_queue_key(self, repo_name)?;
        let id = self.served_repo_id(&repo_root)?;
        let cutover = Cutover {
            expected_epoch,
            residence,
            writer,
            mirror,
        };
        self.cut_origin_authority(&common_dir, &repo_root, id, cutover)
    }
    /// The authority row of a repository this vault serves, by its served name.
    pub fn served_origin_authority(&self, repo_name: &str) -> Result<Option<OriginAuthority>> {
        let repo_root = super::smart_http::origin_repo_dir(self, repo_name)?;
        let id = self.served_repo_id(&repo_root)?;
        self.origin_authority_by_id(id)
    }
    /// What this host holds of the served repository's authority. The host
    /// is this install's machine ([`Vault::local_machine`]): the writer the
    /// owner names when the cutover hands this host the repository. No
    /// request field takes part. The serve path checks a held lease again
    /// under the coordinator, so a cutover between this read and admission
    /// refuses the push.
    pub fn origin_host_authority(&self, repo_name: &str) -> Result<OriginHostAuthority> {
        let repo_root = super::smart_http::origin_repo_dir(self, repo_name)?;
        let repo_id = self.served_repo_id(&repo_root)?;
        let (row, host) = {
            let txn = self.store.env.read_txn()?;
            (
                AUTHORITY.get(&self.store, &txn, &repo_id)?,
                crate::identity::read_machine_id_in_txn(self, &txn)?,
            )
        };
        let Some(row) = row else {
            return Ok(OriginHostAuthority::Unconfigured);
        };
        if row.mirror {
            return Ok(OriginHostAuthority::Mirror(row));
        }
        if host.is_none_or(|host| row.writer != host.to_hex()) {
            return Ok(OriginHostAuthority::Elsewhere(row));
        }
        Ok(OriginHostAuthority::Held(OriginAuthorityLease {
            repo_id,
            epoch: row.epoch,
            writer: row.writer,
        }))
    }
    /// The authority key of a served repository: its object store's identity,
    /// as admission reads it before any commit is pinned.
    fn served_repo_id(&self, repo_root: &Path) -> Result<EntityId> {
        let identity = GitWire::new(self)?.repository_identity(repo_root)?;
        crate::origin::lfs::lfs_repo_id(&identity.as_hex())
    }
    fn cut_origin_authority(
        &self,
        common_dir: &Path,
        repo_root: &Path,
        id: EntityId,
        cutover: Cutover,
    ) -> Result<OriginAuthority> {
        let Cutover {
            expected_epoch,
            residence,
            writer,
            mirror,
        } = cutover;
        let _guard = lock_repository(common_dir)?;
        self.reconcile_receive_pack_operations(repo_root)?;
        // A re-drive of a Published row runs as its own GitWire attempt, which
        // the origin rows do not count: any ref effect still prepared holds
        // the cutover too.
        let wire = GitWire::new(self)?;
        let identity = wire.repository_identity(repo_root)?;
        if self.has_pending_receive_pack_operations(repo_root)?
            || self.prepared_origin_publication_count(id)? != 0
            || wire.has_prepared_ref_effects(identity)?
        {
            return Err(Error::ConcurrentWrite(
                "origin cutover requires a drained publication census",
            ));
        }
        let mut txn = self.store.env.write_txn()?;
        let current = AUTHORITY.get(&self.store, &txn, &id)?;
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
        AUTHORITY.put(&self.store, &mut txn, &id, &row)?;
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
        self.with_write_txn_grouped(|txn| {
            // A publication decided in an earlier epoch cannot be reauthorized.
            if let Some(epoch) = AUTHORITY_PERMIT.get(&self.store, txn, &id)? {
                if epoch != lease.epoch {
                    return Err(Error::ConcurrentWrite(
                        "publication belongs to a previous authority epoch",
                    ));
                }
            } else {
                AUTHORITY_PERMIT.put(&self.store, txn, &id, &lease.epoch)?;
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
        match self.origin_authority_refusal(repo, publication)? {
            Some(refusal) => Err(refusal),
            None => Ok(()),
        }
    }
    /// Why the current authority refuses this publication, or `None` when it
    /// permits it. A read failure is an error, never a refusal.
    pub(in crate::origin) fn origin_authority_refusal(
        &self,
        repo: &GitWireRepo,
        publication: EntityId,
    ) -> Result<Option<Error>> {
        let Some(row) = self.origin_authority(repo)? else {
            return Ok(None);
        };
        if row.mirror {
            return Ok(Some(Error::InvariantViolation(
                "mirror is read-only; import through the authoritative origin",
            )));
        }
        let txn = self.store.env.read_txn()?;
        if AUTHORITY_PERMIT
            .get(&self.store, &txn, &publication)?
            .is_none_or(|epoch| epoch != row.epoch)
        {
            return Ok(Some(Error::ConcurrentWrite(
                "origin publication requires the current authority epoch",
            )));
        }
        Ok(None)
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
        let row = AUTHORITY.get(&self.store, txn, &repo_id)?;
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
