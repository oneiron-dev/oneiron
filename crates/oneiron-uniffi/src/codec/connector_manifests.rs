//! Owned schema JSON inside connector-pack and proxy output manifests.

use oneiron::connector_key::slate::SlateToolManifest;
use oneiron::task_verb::sdk::{ConnectorPackDelta, ConnectorPackView, ProxyConnectorRegistration};

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_connector_pack_view(
    verb: &str,
    mut view: ConnectorPackView,
) -> Result<crate::ConnectorPackView, OneironError> {
    let schemas = take_schemas(&mut view.manifest.tools)?;
    let mut output: crate::ConnectorPackView = lift_record(verb, &view)?;
    put_schemas(&mut output.manifest.tools, schemas);
    Ok(output)
}

pub(crate) fn lift_connector_pack_delta(
    verb: &str,
    mut delta: ConnectorPackDelta,
) -> Result<crate::ConnectorPackDelta, OneironError> {
    let schemas = take_schemas(&mut delta.current.manifest.tools)?;
    let mut output: crate::ConnectorPackDelta = lift_record(verb, &delta)?;
    put_schemas(&mut output.current.manifest.tools, schemas);
    Ok(output)
}

pub(crate) fn lift_proxy_connector_registration(
    verb: &str,
    mut registration: ProxyConnectorRegistration,
) -> Result<crate::ProxyConnectorRegistration, OneironError> {
    let schemas = take_schemas(&mut registration.slate.manifest)?;
    let mut output: crate::ProxyConnectorRegistration = lift_record(verb, &registration)?;
    put_schemas(&mut output.slate.manifest, schemas);
    Ok(output)
}

fn take_schemas(tools: &mut [SlateToolManifest]) -> Result<Vec<Option<WireJson>>, OneironError> {
    let schemas: Vec<_> = tools
        .iter_mut()
        .map(|tool| {
            tool.resolved_input_schema
                .take()
                .filter(|schema| !schema.is_null())
                .map(WireJson::lift)
                .transpose()
        })
        .collect();
    // Drain every tool before returning the first schema conversion error.
    schemas.into_iter().collect()
}

fn put_schemas(tools: &mut [crate::SlateToolManifest], schemas: Vec<Option<WireJson>>) {
    for (tool, schema) in tools.iter_mut().zip(schemas) {
        tool.resolved_input_schema = schema;
    }
}
