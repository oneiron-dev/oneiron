//! FIX 9304: the owner's qualification kit, kept per catalog key, and the
//! audit record of each dependent's re-run after an accepted issuer
//! revision.
//!
//! An owner qualify's kit comes with its request. Each one that qualified a
//! catalog key is kept under that key, in place of the last, so a re-run
//! after the owner accepts an issuer revision qualifies the dependent rows
//! with the kit he last qualified them with. With no kit kept, the re-run
//! lists and screens the connector only, and its record says so. Each
//! dependent's outcome goes on its own key's audit, as the qualify and
//! refresh ops do; the key itself never changes here.

use super::qualification::ConnectorQualificationKit;
use super::record::ConnectorKeyStatus;
use super::txn::{append_connector_key_op_record, read_connector_key_in_txn};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The kit the owner's last successful qualify of a catalog key used. Key:
/// the catalog key's id.
const KITS: SideTable<EntityId, ConnectorQualificationKit, Named> =
    SideTable::new(&side_table::CONNECTOR_QUALIFICATION_KIT);

/// Where a re-run after an accepted issuer revision stopped short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorIssuerRerunStage {
    /// This host installed no transport for the connector.
    NotInstalled,
    /// The catalog key pins no protocol revision.
    Unpinned,
    /// The credential door refused, or another issuer change holds the
    /// connector's credential.
    Credential,
    /// The connector did not list its tools at the pinned revision.
    Discovery,
    /// The listed tools failed screening, or screening could not run.
    Screening,
    /// The connector no longer lists the dependent's row.
    RowUnlisted,
    /// The qualification suite failed, or its kit could not be read.
    Qualification,
}

/// One dependent's re-run after the owner accepted an issuer revision. The
/// accept stands whatever it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorIssuerRerunOutcome {
    /// Discovery, screening and the qualification suite passed on the new
    /// issuer.
    Qualified,
    /// Discovery and screening passed; qualification was not re-run, as no
    /// kit is kept for the catalog key.
    ListedWithoutKit,
    /// The re-run stopped at this stage.
    Failed(ConnectorIssuerRerunStage),
}

impl ConnectorIssuerRerunOutcome {
    /// The key-audit op this outcome records.
    #[must_use]
    pub const fn op(self) -> &'static str {
        match self {
            Self::Qualified => "gate.connector_key.issuer_rerun.qualified",
            Self::ListedWithoutKit => "gate.connector_key.issuer_rerun.listed_without_kit",
            Self::Failed(stage) => match stage {
                ConnectorIssuerRerunStage::NotInstalled => {
                    "gate.connector_key.issuer_rerun.failed.not_installed"
                }
                ConnectorIssuerRerunStage::Unpinned => {
                    "gate.connector_key.issuer_rerun.failed.unpinned"
                }
                ConnectorIssuerRerunStage::Credential => {
                    "gate.connector_key.issuer_rerun.failed.credential"
                }
                ConnectorIssuerRerunStage::Discovery => {
                    "gate.connector_key.issuer_rerun.failed.discovery"
                }
                ConnectorIssuerRerunStage::Screening => {
                    "gate.connector_key.issuer_rerun.failed.screening"
                }
                ConnectorIssuerRerunStage::RowUnlisted => {
                    "gate.connector_key.issuer_rerun.failed.row_unlisted"
                }
                ConnectorIssuerRerunStage::Qualification => {
                    "gate.connector_key.issuer_rerun.failed.qualification"
                }
            },
        }
    }
}

impl Vault {
    /// Keeps `kit` as the one the owner's successful qualify of catalog key
    /// `id` used, in place of any kept before (FIX 9304).
    ///
    /// # Errors
    /// A key that does not resolve, and storage errors.
    pub fn keep_connector_qualification_kit(
        &self,
        id: &EntityId,
        kit: &ConnectorQualificationKit,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if read_connector_key_in_txn(&self.store, &wtxn, id)?.is_none() {
            return Err(Error::EntityNotFound);
        }
        KITS.put(&self.store, &mut wtxn, id, kit)?;
        wtxn.commit()?;
        Ok(())
    }

    /// The kit the owner's last successful qualify of catalog key `id` used;
    /// `None` when none is kept.
    ///
    /// # Errors
    /// Storage errors.
    pub fn connector_qualification_kit(
        &self,
        id: &EntityId,
    ) -> Result<Option<ConnectorQualificationKit>> {
        let txn = self.store.env.read_txn()?;
        KITS.get(&self.store, &txn, id)
    }

    /// Records one dependent key's re-run outcome on its audit, as the
    /// qualify and refresh ops record theirs (FIX 9304); the key itself does
    /// not change. `false` when the key no longer resolves or is revoked:
    /// nothing is recorded.
    ///
    /// # Errors
    /// Storage errors.
    pub fn record_connector_issuer_rerun(
        &self,
        id: &EntityId,
        outcome: ConnectorIssuerRerunOutcome,
    ) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(record) = read_connector_key_in_txn(&self.store, &wtxn, id)?
            .filter(|record| record.status != ConnectorKeyStatus::Revoked)
        else {
            return Ok(false);
        };
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            outcome.op(),
            &record,
            policy.read_frontier_hash()?,
            crate::unix_seconds_now(),
        )?;
        wtxn.commit()?;
        Ok(true)
    }
}
