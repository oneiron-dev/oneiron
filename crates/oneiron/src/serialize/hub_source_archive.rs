//! Credential-safe view of exact replicated skill source carriers. A source
//! member that is no UTF-8 text is an archive file the carrier's row names
//! (FIX 10101). Under the Owner's whole-vault archive with secrets included
//! the record and tree keep credentials; every other export nulls them.
use super::source_tree::HeldFiles;
use super::{ExportBody, ExportSecrets};
use crate::batch::export::{ArchiveFiles, ExportFileTree, ExportSourceContent, FileSpool};
use crate::error::{Error, Result};
use crate::store::skill_package::{HubPackage, SkillCapabilitySurface};
use crate::write_envelope::skill_source::SkillPackageFormat;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportHubSource {
    holder: String,
    record: ExportBody,
    format: SkillPackageFormat,
    source_tree: ExportFileTree,
    bins: BTreeSet<String>,
    env: BTreeSet<String>,
    mcp: BTreeSet<String>,
    allowed_tools: BTreeSet<String>,
}
impl ExportHubSource {
    /// [`Self::from_package_with`] under [`ExportSecrets::Nulled`].
    pub(crate) fn from_package(
        holder: &crate::entity_id::EntityId,
        package: &HubPackage,
    ) -> Result<Self> {
        Self::from_package_with(holder, package, ExportSecrets::Nulled)
    }

    /// A hub package as its carrier under `secrets`: the record via
    /// [`ExportBody::from_bytes_with`], the tree via the source tree's policy
    /// entry. The capability-string credential refusal runs only under
    /// [`ExportSecrets::Nulled`].
    pub(crate) fn from_package_with(
        holder: &crate::entity_id::EntityId,
        package: &HubPackage,
        secrets: ExportSecrets,
    ) -> Result<Self> {
        if secrets == ExportSecrets::Nulled {
            for set in [
                &package.capabilities.bins,
                &package.capabilities.env,
                &package.capabilities.mcp,
                &package.capabilities.allowed_tools,
            ] {
                for text in set {
                    if super::credential_nulling::null_credentials(
                        "",
                        &serde_json::Value::String(text.clone()),
                    ) != serde_json::Value::String(text.clone())
                    {
                        return Err(invalid("source capability credential"));
                    }
                }
            }
        }
        Ok(Self {
            holder: holder.to_hex(),
            record: ExportBody::from_bytes_with(
                &crate::write_envelope::skill_record::encode_skill_record(&package.record)?,
                crate::registry::ENTITY_TYPE_SKILL,
                secrets,
            ),
            format: package.format,
            source_tree: super::source_tree::export_source_tree_for(
                &package.export_files()?,
                secrets,
            )?,
            bins: package.capabilities.bins.clone(),
            env: package.capabilities.env.clone(),
            mcp: package.capabilities.mcp.clone(),
            allowed_tools: package.capabilities.allowed_tools.clone(),
        })
    }
    /// The SKILL entity whose source this carrier holds.
    pub(crate) fn holder(&self) -> Result<crate::entity_id::EntityId> {
        crate::entity_id::EntityId::from_hex(&self.holder)
    }
    /// The source tree this carrier's row holds.
    pub(crate) fn source_tree(&self) -> &ExportFileTree {
        &self.source_tree
    }
    /// Spools the bytes of each source member stored as a file, read from
    /// the carrier `bytes` this source was exported from.
    pub(crate) fn attach_files(&self, bytes: &[u8], spool: &mut FileSpool) -> Result<()> {
        if !self
            .source_tree
            .files
            .iter()
            .any(|file| matches!(file.content, ExportSourceContent::File(_)))
        {
            return Ok(());
        }
        let (_, package) = crate::store::skill_source_carrier::decode_source_carrier(bytes)?
            .ok_or_else(|| invalid("missing source envelope"))?;
        super::source_tree::attach_source_files(&package.export_files()?, &self.source_tree, spool)
    }
    pub(crate) fn redacted(&self) -> bool {
        self.source_tree.content_hash.is_none()
            || self
                .record
                .to_bytes()
                .ok()
                .and_then(|bytes| {
                    crate::write_envelope::skill_record::decode_skill_record(&bytes).ok()
                })
                .is_none()
    }
    /// [`Self::to_bytes_in`] with no archive files.
    /// [`Self::to_bytes_with`] under [`ExportSecrets::Nulled`].
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_bytes_with(ExportSecrets::Nulled)
    }

    /// [`Self::to_bytes_in_with`] with no archive files.
    pub(crate) fn to_bytes_with(&self, secrets: ExportSecrets) -> Result<Vec<u8>> {
        self.to_bytes_in_with(&HeldFiles::default(), secrets)
    }

    /// The carrier's bytes, each source member stored as a file read from
    /// `files`. [`Self::to_bytes_in_with`] under [`ExportSecrets::Nulled`].
    pub(crate) fn to_bytes_in(&self, files: &dyn ArchiveFiles) -> Result<Vec<u8>> {
        self.to_bytes_in_with(files, ExportSecrets::Nulled)
    }

    /// The carrier's bytes under `secrets`, each source member stored as a
    /// file read from `files`: the tree imports with its policy entry, so a
    /// kept credential tree rebuilds its exact package.
    pub(crate) fn to_bytes_in_with(
        &self,
        files: &dyn ArchiveFiles,
        secrets: ExportSecrets,
    ) -> Result<Vec<u8>> {
        if matches!(self.record, ExportBody::Pack(_) | ExportBody::HubSource(_)) {
            return Err(invalid("recursive source carrier"));
        }
        let record =
            crate::write_envelope::skill_record::decode_skill_record(&self.record.to_bytes()?)?;
        let mut package = HubPackage::new(
            record,
            self.source_tree.import_files_in_with(files, secrets)?,
            SkillCapabilitySurface {
                bins: self.bins.clone(),
                env: self.env.clone(),
                mcp: self.mcp.clone(),
                allowed_tools: self.allowed_tools.clone(),
            },
        );
        package.format = self.format;
        crate::store::skill_source_carrier::encode_source_carrier(
            &crate::entity_id::EntityId::from_hex(&self.holder)?,
            &package,
        )
    }

    /// [`Self::validate_in`] with no archive files.
    /// [`Self::validate_with`] under [`ExportSecrets::Nulled`].
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_with(ExportSecrets::Nulled)
    }

    /// [`Self::validate_in_with`] with no archive files.
    pub(crate) fn validate_with(&self, secrets: ExportSecrets) -> Result<()> {
        self.validate_in_with(&HeldFiles::default(), secrets)
    }

    /// The carrier's checks, each source member stored as a file read from
    /// `files`: the same transform over the decoded carrier rebuilds it.
    /// [`Self::validate_in_with`] under [`ExportSecrets::Nulled`].
    pub(crate) fn validate_in(&self, files: &dyn ArchiveFiles) -> Result<()> {
        self.validate_in_with(files, ExportSecrets::Nulled)
    }

    /// The carrier's checks under `secrets`, each source member stored as a
    /// file read from `files`: the record validates with
    /// [`ExportBody::validate_with`], the tree with its policy entry, the
    /// capability-string credential check runs only under
    /// [`ExportSecrets::Nulled`], and the round trip rebuilds through
    /// [`Self::from_package_with`] with the same policy.
    pub(crate) fn validate_in_with(
        &self,
        files: &dyn ArchiveFiles,
        secrets: ExportSecrets,
    ) -> Result<()> {
        let holder = crate::entity_id::EntityId::from_hex(&self.holder)?;
        if holder.to_hex() != self.holder {
            return Err(invalid("noncanonical source holder"));
        }

        if matches!(self.record, ExportBody::Pack(_) | ExportBody::HubSource(_)) {
            return Err(invalid("recursive source carrier"));
        }
        self.record
            .validate_with(crate::registry::ENTITY_TYPE_SKILL, secrets)?;
        self.source_tree.validate_in_with(files, secrets)?;
        if secrets == ExportSecrets::Nulled {
            for set in [&self.bins, &self.env, &self.mcp, &self.allowed_tools] {
                for text in set {
                    if super::credential_nulling::null_credentials(
                        "",
                        &serde_json::Value::String(text.clone()),
                    ) != serde_json::Value::String(text.clone())
                    {
                        return Err(invalid("source capability credential"));
                    }
                }
            }
        }
        if !self.redacted() {
            let (holder, package) = crate::store::skill_source_carrier::decode_source_carrier(
                &self.to_bytes_in_with(files, secrets)?,
            )?
            .ok_or_else(|| invalid("missing source envelope"))?;
            if Self::from_package_with(&holder, &package, secrets)? != *self {
                return Err(invalid("noncanonical source carrier"));
            }
        }
        Ok(())
    }
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("hub source archive: {reason}"))
}
