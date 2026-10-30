//! A built-in connector pack's isolated probe (FIX 710). The host runs each
//! declared connection's own read-only identity call through the channel's
//! client, on fresh transports, and the answers qualify the exact embedded
//! source. A probe never blocks a built-in its checked setup qualifies: a
//! probe that cannot run, or fails, leaves the setup check to qualify it.
//! Entry: `BuiltinProbeQualifier`. The suite's own checks stay in `qualify`.

use serde_json::{Value, json};

use super::*;
use crate::connector_key::qualification::{
    BUILTIN_PROBE_QUALIFICATION_SUITE, ProbeDisposition, ProbeReply, ProbeRequest,
    QualificationConnector, QualificationFailure,
};
use crate::connector_key::{PackConnectionCheck, PackConnectionVerifier};

/// Qualifies a built-in connector on the host's isolated probes of its
/// checked connections, else on its checked setup ([`SetupCheckQualifier`]).
/// Each connection's probe must answer for the account its Verified check
/// bound, on two fresh connections alike, with no write, while the channel's
/// state and the vault's check record stand as they were.
pub struct BuiltinProbeQualifier<'a> {
    pub vault: &'a Vault,
    pub verifier: &'a dyn PackConnectionVerifier,
}

impl PackQualifier for BuiltinProbeQualifier<'_> {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification> {
        match self.probe(source) {
            Ok(qualified) => Ok(qualified),
            Err(reason) => {
                tracing::info!(
                    pack = %source.manifest().name,
                    %reason,
                    "built-in probe did not qualify the pack; its checked setup does"
                );
                SetupCheckQualifier { vault: self.vault }.qualify(source)
            }
        }
    }
}

impl BuiltinProbeQualifier<'_> {
    /// Every declared connection probed in turn; the first that cannot run
    /// or fails is the reason.
    fn probe(&self, source: &PackSource) -> std::result::Result<PackQualification, String> {
        let manifest = source.manifest();
        let Some(PackAdapter::Builtin(channel)) = manifest.adapter.as_ref() else {
            return Err("only a built-in connector runs an isolated probe".to_owned());
        };
        let embedded =
            super::super::builtin::embedded_builtin_source(channel).map_err(|e| e.to_string())?;
        if manifest.kind != PackKind::Connector || embedded.content_hash() != source.content_hash()
        {
            return Err("a probe qualifies only the embedded built-in source".to_owned());
        }
        let setup = manifest
            .setup
            .as_ref()
            .filter(|setup| !setup.connections.is_empty())
            .ok_or_else(|| "the built-in declares no setup connection to probe".to_owned())?;
        let source_hash = source.content_hash().to_hex();
        let mut report =
            blake3::Hasher::new_derive_key("oneiron.pack.builtin-probe-qualification.v1");
        let mut frame = |part: &[u8]| {
            report.update(&(part.len() as u64).to_le_bytes());
            report.update(part);
        };
        frame(source_hash.as_bytes());
        let mut probed = Vec::with_capacity(setup.connections.len());
        for connection in &setup.connections {
            let verified = || {
                self.vault
                    .require_candidate_pack_connection_verified(
                        &manifest.name,
                        &source_hash,
                        &connection.id,
                    )
                    .map_err(|error| error.to_string())
            };
            let checked = verified()?;
            // The probe compares the account, not scopes: the check judged
            // those against the owner's allowed permissions already.
            let check = PackConnectionCheck {
                pack: &manifest.name,
                connection: &connection.id,
                check: &connection.verify,
                auth: connection.auth,
                secrets: &connection.secrets,
                allowed_scopes: &[],
            };
            let connector = self
                .verifier
                .builtin_probe(self.vault, check)
                .ok_or_else(|| format!("this host runs no probe for {}", connection.verify))?;
            let (answer, state) = probe_connection(connector.as_ref(), &connection.verify)?;
            let named = answer
                .result
                .get("provider_account")
                .and_then(Value::as_str);
            if checked.provider_account.is_none() || named != checked.provider_account.as_deref() {
                return Err(format!(
                    "the {} probe answered for another account than its check bound",
                    connection.id
                ));
            }
            if verified()? != checked {
                return Err(format!(
                    "the {} check moved during its probe",
                    connection.id
                ));
            }
            frame(connection.id.as_bytes());
            frame(connection.verify.as_bytes());
            frame(answer.result.to_string().as_bytes());
            frame(&state);
            frame(checked.basis.as_bytes());
            frame(&checked.checked_at.to_be_bytes());
            probed.push(format!("{} ({})", connection.id, connection.verify));
        }
        let report_hash = report.finalize().to_hex().to_string();
        let receipt = PackConnectorReceipt {
            source_hash: source_hash.clone(),
            qualification: ConnectorQualificationReceipt::builtin_probe(
                report_hash.clone(),
                env!("CARGO_PKG_VERSION").to_owned(),
                *source.content_hash().as_bytes(),
                crate::unix_seconds_now(),
            )
            .map_err(|error| error.to_string())?,
        };
        let qualified = PackQualification {
            suite: BUILTIN_PROBE_QUALIFICATION_SUITE.to_owned(),
            report_hash,
            passed: true,
            advisory_accepted: true,
            advisory: format!(
                "Built-in connector {} qualified on its isolated probe: {}.",
                manifest.name,
                probed.join(", ")
            ),
            runtime: None,
            connector: Some(ConnectorPackQualification {
                receipt,
                runtime: None,
            }),
        };
        validate_qualification(source, &qualified).map_err(|error| error.to_string())?;
        Ok(qualified)
    }
}

/// One connection's probe: two fresh connections list the same one
/// read-only identity tool and answer it alike, with no write, and the
/// channel's state, read on a transport of its own, stands as it was.
/// Returns the answer and that state.
fn probe_connection(
    connector: &dyn QualificationConnector,
    check: &str,
) -> std::result::Result<(ProbeReply, Vec<u8>), String> {
    let failed = |failure: QualificationFailure| failure.to_string();
    let mut first = connector.connect().map_err(failed)?;
    let mut second = connector.connect().map_err(failed)?;
    let tools = first.tools_list().map_err(failed)?;
    if tools != second.tools_list().map_err(failed)? {
        return Err("the probe's connections list different tools".to_owned());
    }
    let [tool] = tools.as_slice() else {
        return Err("the probe lists other tools than its identity call".to_owned());
    };
    if tool.name != check || tool.writes {
        return Err("the probe's tool is not the connection's read-only check".to_owned());
    }
    let before = connector.effect_state().map_err(failed)?;
    let request = |connection: &str| ProbeRequest {
        id: format!("{check}.{connection}"),
        name: check.to_owned(),
        arguments: json!({}),
    };
    let answer = first.call(&request("first")).map_err(failed)?;
    let again = second.call(&request("second")).map_err(failed)?;
    if answer.disposition != ProbeDisposition::Answer {
        return Err(answer
            .result
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("the provider refused the probe")
            .to_owned());
    }
    if again.disposition != answer.disposition
        || again.result_type != answer.result_type
        || again.result != answer.result
        || !tool.result_types.contains(&answer.result_type)
    {
        return Err("the probe's connections answered differently".to_owned());
    }
    if !answer.writes.is_empty() || !again.writes.is_empty() {
        return Err("the probe reported a write".to_owned());
    }
    if connector.effect_state().map_err(failed)? != before {
        return Err("the channel's state moved during the probe".to_owned());
    }
    Ok((answer, before))
}
