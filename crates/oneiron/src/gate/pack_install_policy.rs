//! Vault-resident connector-pack install rows; default behavior is shipped data.
//! Grammar and resource-safety ceilings stay in code. Rows may only narrow
//! the analyzed operation set and add refusal patterns; holder rows are capped
//! by the vault row under the manifest's explicit precedence.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::{Vault, write_envelope::skill_record::SkillContentHash};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Cursor;

pub(super) const KEY: &str = "pack_install_policy";

#[doc(hidden)]
pub use oneiron_records::gate::pack_install_policy::PackInstallPolicyOverride;
#[doc(hidden)]
pub(crate) use oneiron_records::gate::pack_install_policy::{
    EffectivePackInstallPolicy, HolderInstallRow, PackInstallPolicy, PackInstallPrecedence,
    PackInstallRuleRow,
};

impl Vault {
    /// Update one owner-authored row in the pinned, trusted policy manifest.
    /// The default vault row and unrelated policy axes are never replaced.
    pub(crate) fn update_pack_install_policy(
        &self,
        owner: &AuthenticatedOwner,
        f: impl FnOnce(&mut PackInstallPolicy) -> Result<()>,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let id = super::default_manifest::default_policy_manifest_id()?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                return Err(Error::CorruptedIndex("policy manifest type"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let mut cursor = Cursor::new(body);
            let mut manifest = rmpv::decode::read_value(&mut cursor)
                .map_err(|_| Error::CorruptedIndex("pack install policy manifest"))?;
            if cursor.position() != body.len() as u64 {
                return Err(Error::CorruptedIndex("pack install policy trailing bytes"));
            }
            let Value::Map(entries) = &mut manifest else {
                return Err(Error::CorruptedIndex("policy manifest map"));
            };
            let mut index = None;
            for (i, (key, _)) in entries.iter().enumerate() {
                if key.as_str() == Some(KEY) && index.replace(i).is_some() {
                    return Err(Error::CorruptedIndex("duplicate pack install policy"));
                }
            }
            let index = index.ok_or(Error::CorruptedIndex("pack install policy missing"))?;
            let mut policy = PackInstallPolicy::decode(entries[index].1.clone())
                .ok_or(Error::CorruptedIndex("pack install policy invalid"))?;
            f(&mut policy)?;
            if !policy.validate() {
                return Err(Error::InvalidConfig("invalid pack install policy".into()));
            }
            entries[index].1 = policy.encode();
            let mut data = Vec::new();
            rmpv::encode::write_value(&mut data, &manifest)
                .map_err(|_| Error::InvariantViolation("pack policy manifest encoding"))?;
            self.write_owner_policy_manifest_in_txn(owner, txn, id, data, crate::unix_seconds_now())
        })?;
        // A floor this commit moved is judged again at once (FIX 5505).
        self.apply_pending_rebinds_after_commit();
        Ok(())
    }
}
