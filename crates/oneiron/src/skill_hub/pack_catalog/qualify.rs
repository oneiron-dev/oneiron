//! Connector packs use the engine's real wire probes, never a publisher's grade.
//! A built-in rides its checked setup connection instead.
use super::{
    PackAdapter, PackFitPolicy, PackFitVerdict, PackInstallReceipt, PackInstallStatus, PackKind,
    PackObservedTool, PackPermissions, PackQualification, PackQualifier, PackRuntimeRecipe,
    PackSource, invalid,
};
use crate::Vault;
use crate::connector_key::qualification::{
    CONNECTOR_QUALIFICATION_SUITE, ConnectorQualificationReceipt, SETUP_CHECK_QUALIFICATION_SUITE,
};
use crate::connector_key::{
    ConnectorManifestQualifier, ProbeManifestQualifier, ResolvedConnectorManifest,
};
use crate::error::Result;
use crate::skill::SkillContentHash;
use serde::{Deserialize, Serialize};

/// Source identity and the contract evidence retained in the installed receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackConnectorReceipt {
    pub source_hash: String,
    pub qualification: ConnectorQualificationReceipt,
}

/// Only the engine probe adapter constructs this token. A host may accept the
/// advisory, but cannot turn a boolean script grade into connector admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorPackQualification {
    receipt: PackConnectorReceipt,
    runtime: Option<PackRuntimeRecipe>,
}
impl ConnectorPackQualification {
    pub fn receipt(&self) -> &PackConnectorReceipt {
        &self.receipt
    }
}

/// The host binds these independent, isolated connections to the exact source
/// and runtime. Probe effects must use its sandbox under the object's grant,
/// not the pending pack's live route. Built-in and hub adapters use this alike.
pub struct ProbePackQualifier<'a> {
    pub source_hash: SkillContentHash,
    pub manifest: &'a ResolvedConnectorManifest,
    pub protocol_revision: &'a str,
    pub probes: ProbeManifestQualifier<'a>,
    pub runtime: Option<PackRuntimeRecipe>,
    pub advisory_accepted: bool,
    pub advisory: &'a str,
}
impl PackQualifier for ProbePackQualifier<'_> {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification> {
        if source.manifest().kind != PackKind::Connector
            || source.content_hash() != self.source_hash
        {
            return Err(invalid("connector probes do not bind this source"));
        }
        // Validate the frozen advisory and runtime before invoking effectful probes.
        validate_advisory(
            CONNECTOR_QUALIFICATION_SUITE,
            self.advisory_accepted,
            self.advisory,
        )?;
        validate_runtime(source, self.runtime.as_ref())?;
        let report_hash = self.probes.qualify(self.manifest, self.protocol_revision)?;
        let receipt = PackConnectorReceipt {
            source_hash: source.content_hash().to_hex(),
            qualification: ConnectorQualificationReceipt::new(
                report_hash.clone(),
                self.protocol_revision.to_owned(),
                self.manifest.hash()?,
                crate::unix_seconds_now(),
            )?,
        };
        let qualified = PackQualification {
            suite: CONNECTOR_QUALIFICATION_SUITE.to_owned(),
            report_hash,
            passed: true,
            advisory_accepted: self.advisory_accepted,
            advisory: self.advisory.to_owned(),
            runtime: self.runtime.clone(),
            connector: Some(ConnectorPackQualification {
                receipt,
                runtime: self.runtime.clone(),
            }),
        };
        validate_qualification(source, &qualified)?;
        Ok(qualified)
    }
}

/// A built-in connector pack qualifies on its checked setup connection, not
/// a probe suite (Engine ruling 10-17). The probe suite proves an untrusted
/// pack's behaviour; a built-in is the engine's own hash-verified code, and a
/// Verified check proves the credential path: live grants, a stored
/// credential and the declared provider check on the current basis. It
/// qualifies only the exact embedded source, so a hub pack cannot ride it.
pub struct SetupCheckQualifier<'a> {
    pub vault: &'a Vault,
}
impl PackQualifier for SetupCheckQualifier<'_> {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification> {
        let manifest = source.manifest();
        let Some(PackAdapter::Builtin(channel)) = manifest.adapter.as_ref() else {
            return Err(invalid("only a built-in connector qualifies on its setup check"));
        };
        if manifest.kind != PackKind::Connector
            || super::builtin::embedded_builtin_source(channel)?.content_hash()
                != source.content_hash()
        {
            return Err(invalid("a setup check qualifies only the embedded built-in source"));
        }
        let setup = manifest
            .setup
            .as_ref()
            .ok_or_else(|| invalid("the built-in declares no setup connection to check"))?;
        let source_hash = source.content_hash().to_hex();
        let mut report = blake3::Hasher::new_derive_key("oneiron.pack.setup-check-qualification.v1");
        let mut frame = |part: &[u8]| {
            report.update(&(part.len() as u64).to_le_bytes());
            report.update(part);
        };
        frame(source_hash.as_bytes());
        let mut checked = Vec::with_capacity(setup.connections.len());
        for connection in &setup.connections {
            let check = self.vault.require_candidate_pack_connection_verified(
                &manifest.name,
                &source_hash,
                &connection.id,
            )?;
            frame(connection.id.as_bytes());
            frame(connection.verify.as_bytes());
            frame(check.account.as_deref().unwrap_or_default().as_bytes());
            frame(check.evidence.as_deref().unwrap_or_default().as_bytes());
            frame(check.basis.as_bytes());
            frame(&check.checked_at.to_be_bytes());
            checked.push(format!("{} ({})", connection.id, connection.verify));
        }
        if checked.is_empty() {
            return Err(invalid("the built-in declares no setup connection to check"));
        }
        let report_hash = report.finalize().to_hex().to_string();
        let receipt = PackConnectorReceipt {
            source_hash: source_hash.clone(),
            qualification: ConnectorQualificationReceipt::setup_check(
                report_hash.clone(),
                env!("CARGO_PKG_VERSION").to_owned(),
                *source.content_hash().as_bytes(),
                crate::unix_seconds_now(),
            )?,
        };
        let qualified = PackQualification {
            suite: SETUP_CHECK_QUALIFICATION_SUITE.to_owned(),
            report_hash,
            passed: true,
            advisory_accepted: true,
            advisory: format!(
                "Built-in connector {} qualified on its checked setup: {}.",
                manifest.name,
                checked.join(", ")
            ),
            runtime: None,
            connector: Some(ConnectorPackQualification {
                receipt,
                runtime: None,
            }),
        };
        validate_qualification(source, &qualified)?;
        Ok(qualified)
    }
}

/// Compose a host's existing fit policy with the engine connector probe adapter.
pub struct QualifiedPackFitPolicy<'a> {
    pub fit: &'a dyn PackFitPolicy,
    pub qualifier: &'a dyn PackQualifier,
}
impl PackFitPolicy for QualifiedPackFitPolicy<'_> {
    fn evaluate(
        &self,
        source: &PackSource,
        permissions: &PackPermissions,
    ) -> Result<PackFitVerdict> {
        self.fit.evaluate(source, permissions)
    }
    fn qualify_script(&self, source: &PackSource) -> Result<Option<PackQualification>> {
        self.fit.qualify_script(source)
    }
    fn qualify_connector(&self, source: &PackSource) -> Result<Option<PackQualification>> {
        self.qualifier.qualify(source).map(Some)
    }
    fn observed_tools(&self, source: &PackSource) -> Result<Vec<PackObservedTool>> {
        self.fit.observed_tools(source)
    }
}

pub(super) fn validate_qualification(
    source: &PackSource,
    result: &PackQualification,
) -> Result<()> {
    if !result.passed {
        return Err(invalid("pack qualification refused"));
    }
    SkillContentHash::parse_hex(&result.report_hash)?;
    validate_advisory(&result.suite, result.advisory_accepted, &result.advisory)?;
    validate_runtime(source, result.runtime.as_ref())?;
    if source.manifest().kind == PackKind::Connector {
        let connector = result
            .connector
            .as_ref()
            .ok_or_else(|| invalid("connector pack requires engine contract probes"))?;
        validate_connector_evidence(source, &connector.receipt, &result.report_hash)?;
        if connector.runtime != result.runtime
            || result.suite != connector.receipt.qualification.suite
        {
            return Err(invalid("connector qualification runtime or suite changed"));
        }
    } else if result.connector.is_some() {
        return Err(invalid("connector qualification requires a connector pack"));
    }
    Ok(())
}

fn validate_advisory(suite: &str, accepted: bool, advisory: &str) -> Result<()> {
    if !accepted
        || suite.is_empty()
        || suite.len() > 256
        || advisory.is_empty()
        || advisory.len() > 16384
    {
        return Err(invalid("pack qualification advisory refused"));
    }
    for text in [suite, advisory] {
        crate::batch::secret_scan::scan_metadata_field(text)?;
    }
    Ok(())
}

fn validate_runtime(source: &PackSource, runtime: Option<&PackRuntimeRecipe>) -> Result<()> {
    match source.manifest().adapter.as_ref() {
        Some(adapter @ PackAdapter::Script(_)) => {
            let runtime =
                runtime.ok_or_else(|| invalid("script pack requires qualified runtime recipe"))?;
            if &runtime.adapter != adapter
                || runtime.runtime_id.is_empty()
                || runtime.runtime_id.len() > 1024
            {
                return Err(invalid("runtime recipe does not bind declared adapter"));
            }
            SkillContentHash::parse_hex(&runtime.runtime_hash)?;
            super::script_plan::ScriptExecutionPlan::from_source(source, runtime)?
                .qualified_shape()?;
            crate::batch::secret_scan::scan_metadata_field(&runtime.runtime_id)?;
        }
        _ if runtime.is_some() => {
            return Err(invalid("only a script adapter declares a foreign runtime"));
        }
        _ => {}
    }
    Ok(())
}

fn validate_connector_evidence(
    source: &PackSource,
    receipt: &PackConnectorReceipt,
    report_hash: &str,
) -> Result<()> {
    if receipt.qualification.suite == SETUP_CHECK_QUALIFICATION_SUITE {
        if !matches!(source.manifest().adapter, Some(PackAdapter::Builtin(_))) {
            return Err(invalid("only a built-in connector qualifies on its setup check"));
        }
        receipt.qualification.validate_setup_check()?;
    } else {
        receipt.qualification.validate()?;
    }
    if source.manifest().kind != PackKind::Connector
        || receipt.source_hash != source.content_hash().to_hex()
        || receipt.qualification.report_hash != report_hash
    {
        return Err(invalid("connector qualification source or report changed"));
    }
    Ok(())
}

pub(super) fn validate_installed_qualification(
    source: &PackSource,
    receipt: &PackInstallReceipt,
) -> Result<()> {
    match receipt.connector_qualification.as_ref() {
        Some(qualification) => validate_connector_evidence(
            source,
            qualification,
            receipt
                .qualification_report_hash
                .as_deref()
                .ok_or_else(|| invalid("connector qualification report missing"))?,
        ),
        None if source.manifest().kind == PackKind::Connector
            && receipt.status == PackInstallStatus::Active =>
        {
            Err(invalid("active connector pack lacks qualification receipt"))
        }
        None => Ok(()),
    }
}
