//! Credential-safe view of exact replicated skill source carriers. A source
//! member that is no UTF-8 text is an archive file the carrier's row names
//! (FIX 10101).
use super::ExportBody;
use super::source_tree::HeldFiles;
use crate::batch::export::{ArchiveFiles, ExportFileTree, ExportSourceContent, FileSpool};
use crate::error::{Error, Result};
use crate::skill_hub::{HubPackage, SkillCapabilitySurface, SkillPackageFormat};
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
    pub(crate) fn from_package(
        holder: &crate::entity_id::EntityId,
        package: &HubPackage,
    ) -> Result<Self> {
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
        Ok(Self {
            holder: holder.to_hex(),
            record: ExportBody::from_bytes(
                &crate::skill::encode_skill_record(&package.record)?,
                crate::registry::ENTITY_TYPE_SKILL,
            ),
            format: package.format,
            source_tree: super::export_source_tree(&package.export_files()?)?,
            bins: package.capabilities.bins.clone(),
            env: package.capabilities.env.clone(),
            mcp: package.capabilities.mcp.clone(),
            allowed_tools: package.capabilities.allowed_tools.clone(),
        })
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
        let (_, package) = crate::skill_hub::decode_source_carrier(bytes)?
            .ok_or_else(|| invalid("missing source envelope"))?;
        super::source_tree::attach_source_files(&package.export_files()?, &self.source_tree, spool)
    }
    pub(crate) fn redacted(&self) -> bool {
        self.source_tree.content_hash.is_none()
            || self
                .record
                .to_bytes()
                .ok()
                .and_then(|bytes| crate::skill::decode_skill_record(&bytes).ok())
                .is_none()
    }
    /// [`Self::to_bytes_in`] with no archive files.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_bytes_in(&HeldFiles::default())
    }
    /// The carrier's bytes, each source member stored as a file read from
    /// `files`.
    pub(crate) fn to_bytes_in(&self, files: &dyn ArchiveFiles) -> Result<Vec<u8>> {
        if matches!(self.record, ExportBody::Pack(_) | ExportBody::HubSource(_)) {
            return Err(invalid("recursive source carrier"));
        }
        let record = crate::skill::decode_skill_record(&self.record.to_bytes()?)?;
        let mut package = HubPackage::new(
            record,
            self.source_tree.import_files_in(files)?,
            SkillCapabilitySurface {
                bins: self.bins.clone(),
                env: self.env.clone(),
                mcp: self.mcp.clone(),
                allowed_tools: self.allowed_tools.clone(),
            },
        );
        package.format = self.format;
        crate::skill_hub::encode_source_carrier(
            &crate::entity_id::EntityId::from_hex(&self.holder)?,
            &package,
        )
    }
    /// [`Self::validate_in`] with no archive files.
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_in(&HeldFiles::default())
    }
    /// The carrier's checks, each source member stored as a file read from
    /// `files`: the same transform over the decoded carrier rebuilds it.
    pub(crate) fn validate_in(&self, files: &dyn ArchiveFiles) -> Result<()> {
        let holder = crate::entity_id::EntityId::from_hex(&self.holder)?;
        if holder.to_hex() != self.holder {
            return Err(invalid("noncanonical source holder"));
        }

        if matches!(self.record, ExportBody::Pack(_) | ExportBody::HubSource(_)) {
            return Err(invalid("recursive source carrier"));
        }
        self.record.validate(crate::registry::ENTITY_TYPE_SKILL)?;
        self.source_tree.validate_in(files)?;
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
        if !self.redacted() {
            let (holder, package) =
                crate::skill_hub::decode_source_carrier(&self.to_bytes_in(files)?)?
                    .ok_or_else(|| invalid("missing source envelope"))?;
            if Self::from_package(&holder, &package)? != *self {
                return Err(invalid("noncanonical source carrier"));
            }
        }
        Ok(())
    }
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("hub source archive: {reason}"))
}
