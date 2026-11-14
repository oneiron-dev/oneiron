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
    EffectivePackInstallPolicy, HolderInstallRow, PackInstallPrecedence, PackInstallRuleRow,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackInstallPolicy {
    pub precedence: PackInstallPrecedence,
    pub vault: PackInstallRuleRow,
    pub owner: PackInstallRuleRow,
    pub holders: Vec<HolderInstallRow>,
}
impl PackInstallPolicy {
    pub(crate) fn shipped() -> Self {
        serde_json::from_str(include_str!("pack_install_defaults.json"))
            .expect("shipped install policy must decode")
    }
    pub(crate) fn decode(value: Value) -> Option<Self> {
        let policy: Self = rmpv::ext::from_value(value).ok()?;
        policy.validate().then_some(policy)
    }
    pub(crate) fn encode(&self) -> Value {
        rmpv::ext::to_value(self).expect("validated install policy must encode")
    }
    fn validate(&self) -> bool {
        self.vault.validate()
            && self
                .vault
                .allowed_calls
                .as_ref()
                .is_some_and(|calls| !calls.is_empty())
            && self.owner.validate()
            && self.holders.iter().all(|row| {
                !row.holder_ref.trim().is_empty()
                    && row.holder_ref.len() <= 256
                    && row.rules.validate()
            })
            && self
                .holders
                .iter()
                .map(|row| row.holder_ref.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == self.holders.len()
    }
    pub(crate) fn restrict(&mut self, other: Self) {
        self.vault.restrict(other.vault);
        self.owner.restrict(other.owner);
        for holder in other.holders {
            if let Some(existing) = self
                .holders
                .iter_mut()
                .find(|row| row.holder_ref == holder.holder_ref)
            {
                existing.rules.restrict(holder.rules);
            } else {
                self.holders.push(holder);
            }
        }
    }
    pub(crate) fn effective(&self, holder: &str) -> EffectivePackInstallPolicy {
        let mut effective = EffectivePackInstallPolicy {
            hidden_instructions: Vec::new(),
            parameter_injection: Vec::new(),
            allowed_calls: self
                .vault
                .allowed_calls
                .as_ref()
                .expect("validated vault row")
                .iter()
                .cloned()
                .collect(),
            known_bad_patterns: Vec::new(),
            removed_hashes: Vec::new(),
        };
        self.vault.apply(&mut effective);
        self.owner.apply(&mut effective);
        if let Some(row) = self.holders.iter().find(|row| row.holder_ref == holder) {
            row.rules.apply(&mut effective);
        }
        effective
    }
}

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
