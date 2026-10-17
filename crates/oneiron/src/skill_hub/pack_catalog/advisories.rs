//! OSV advisories for a pack tree and each bundled skill (OF-213). The query
//! runs before the writer; its receipts co-commit with the staged bytes, so
//! the install door and each bundled skill's activation consult read them.
use super::PackSource;
use super::bundled_skills::bundled_skill_packages;
use crate::skill::SkillContentHash;
use crate::skill_hub::osv::{self, OSV_SCAN_PROVIDER, OsvDevClient};
use crate::skill_hub::support::map_text;
use crate::skill_hub::{ScanRiskLevel, SkillScanReceipt};
use crate::{TimeRange, Vault, error::Result};

/// The advisory receipts one pack's bytes earned, by content hash: the
/// whole tree first, then each bundled skill.
pub(super) struct PackAdvisories {
    receipts: Vec<(SkillContentHash, SkillScanReceipt)>,
}

impl Vault {
    /// Query OSV for the pack tree's dependencies and, when `bundled`, each
    /// bundled skill's. Holds no storage transaction.
    pub(super) fn pack_advisories(
        &self,
        source: &PackSource,
        bundled: bool,
        learned_at: u64,
    ) -> Result<PackAdvisories> {
        let mut trees = vec![(
            source.content_hash(),
            osv::files_dependency_inventory(&source.files)?,
        )];
        if bundled {
            for (_, package) in bundled_skill_packages(source)? {
                trees.push((
                    package.content_hash()?,
                    osv::dependency_inventory(&package)?,
                ));
            }
        }
        let mut receipts = Vec::new();
        for (hash, coordinates) in trees {
            let (_, _, scans) =
                self.dependency_advisories(hash, &coordinates, &OsvDevClient, learned_at)?;
            receipts.extend(scans.into_iter().map(|scan| (hash, scan)));
        }
        Ok(PackAdvisories { receipts })
    }

    pub(super) fn ingest_pack_advisories_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        advisories: &PackAdvisories,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        for (hash, receipt) in &advisories.receipts {
            self.ingest_scan_verdict_for_hash_in_txn(txn, *hash, receipt, occurred, learned_at)?;
        }
        Ok(())
    }

    /// A hub source waits for the owner when its OSV row names an advisory
    /// or the query did not complete; no OSV row means no dependencies.
    pub(super) fn pack_advisory_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hash: SkillContentHash,
    ) -> Result<bool> {
        for body in
            crate::skill_hub::skill_scan_verdicts_for_content_hash_in_store(&self.store, txn, hash)?
        {
            if map_text(&body.value, "provider") == Some(OSV_SCAN_PROVIDER)
                && (crate::skill_hub::scan_verdict_row_risk(&body)? != ScanRiskLevel::None
                    || map_text(&body.value, "completeness") == Some("partial"))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
