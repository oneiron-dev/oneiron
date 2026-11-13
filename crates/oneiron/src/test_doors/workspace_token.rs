//! Door for `tests/microsoft_excel_wire.rs` (L3-17-EXCEL-CONNECTION = B):
//! the access token a workspace module's connection presents for a stored
//! grant, on a client whose every request goes to a closed local port (or a
//! test's own proxy), so a token exchange the step tries fails instead of
//! reaching a provider.

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
    access_token_via(name, grant, "http://127.0.0.1:9")
}

/// [`access_token_offline`] with every request sent through the proxy at
/// `proxy` (`http://127.0.0.1:<port>`), so a test sees the host an exchange
/// the step tries reaches ([MICROSOFT365-OAUTH-EXCHANGE]).
///
/// # Errors
///
/// As [`access_token_offline`]'s.
pub fn access_token_via(name: &str, grant: &[u8], proxy: &str) -> Result<String> {
    let api =
        module(name).ok_or_else(|| Error::InvalidConfig(format!("no workspace module {name}")))?;
    let client = super::microsoft_token::proxied_client(proxy)?;
    workspace_connector::connection_access_token(api, &client, grant)
        .map(|token| token.as_str().to_owned())
}
