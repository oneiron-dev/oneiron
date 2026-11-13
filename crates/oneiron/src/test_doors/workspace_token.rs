//! Door for `tests/microsoft_excel_wire.rs` (L3-17-EXCEL-CONNECTION = B):
//! the access token a workspace module's connection presents for a stored
//! grant, on a client whose every request goes to a closed local port, so a
//! token exchange the step tries fails instead of reaching a provider.

use crate::channel_identity_provider::workspace_connector::{self, module};
use crate::error::{Error, Result};

/// The access token the connection of the module named `name` presents for
/// the stored grant `grant`.
///
/// # Errors
///
/// No such module, the client does not build, or the token step failed, as
/// an exchange it tried does.
pub fn access_token_offline(name: &str, grant: &[u8]) -> Result<String> {
    let api =
        module(name).ok_or_else(|| Error::InvalidConfig(format!("no workspace module {name}")))?;
    let closed = reqwest::Proxy::all("http://127.0.0.1:9")
        .map_err(|_| Error::InvalidConfig("closed-port proxy did not build".to_owned()))?;
    let client = reqwest::blocking::Client::builder()
        .proxy(closed)
        .build()
        .map_err(|_| Error::InvalidConfig("offline client did not build".to_owned()))?;
    workspace_connector::connection_access_token(api, &client, grant)
        .map(|token| token.as_str().to_owned())
}
