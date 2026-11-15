//! A built-in Google module through `connector.schema` (L3-17, PR 1): with no
//! checked Google connection it names the one Google connection
//! (`google_connection_not_checked`), and an unknown tool is unknown.
//! Uses only doors main has, so its red on main is a wrong value, not a
//! missing door.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test google_connection_routes`

use oneiron::verbs::{ConnectorSchemaRequest, connector_schema_read};
use oneiron::{EdgeActorClass, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn an_unconnected_google_module_answers_connection_not_checked() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let reply = connector_schema_read(
        &memory,
        ConnectorSchemaRequest {
            name: "google.sheets".to_owned(),
            source: None,
            tool: "values.batchGet".to_owned(),
        },
    )?;
    assert_eq!(reply.input_schema, None);
    assert_eq!(
        reply.reasons,
        vec!["google_connection_not_checked".to_owned()],
        "a vault with no checked Google connection names the Google connection"
    );
    let unknown = connector_schema_read(
        &memory,
        ConnectorSchemaRequest {
            name: "google.sheets".to_owned(),
            source: None,
            tool: "values.clear".to_owned(),
        },
    )?;
    assert_eq!(unknown.reasons, vec!["connector_tool_unknown".to_owned()]);
    Ok(())
}
