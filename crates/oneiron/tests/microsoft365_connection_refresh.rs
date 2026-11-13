//! The Microsoft 365 connection refreshes the grant the Microsoft code
//! exchange stores, and a Microsoft grant never reaches Google's token
//! endpoint ([MICROSOFT365-OAUTH-EXCHANGE]; RULING L3-17-EXCEL-CONNECTION,
//! 14 Nov 06:23). The door's client sends every request to a closed local
//! port, so a refresh the token step tries fails instead of reaching a
//! provider, and its error names the endpoint it was for.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test microsoft365_connection_refresh`

use oneiron::channel_identity_provider::gmail::gmail_authorization;
use oneiron::test_doors::workspace_token::access_token_offline;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// What the Microsoft code exchange stores: a refresh token, its OAuth
/// client and the tenant the sign-in ran against.
const MICROSOFT_TEST_GRANT: &[u8] = br#"{"access_token":"ms-access","refresh_token":"ms-refresh","client_id":"ms-client","client_secret":"ms-secret","tenant":"organizations","scope":"https://graph.microsoft.com/Files.ReadWrite"}"#;

#[test]
fn the_microsoft365_connection_refreshes_an_exchanged_grant() -> TestResult {
    let refused = access_token_offline("microsoft.excel", MICROSOFT_TEST_GRANT)
        .expect_err("the connection refreshes the grant instead of presenting its stored token");
    assert!(
        refused
            .to_string()
            .contains("Microsoft's token endpoint could not be reached"),
        "the refresh went to Microsoft's token endpoint: {refused}"
    );
    // A grant that names no tenant is not one the exchange stored: its
    // access token is presented as it is, and nothing is exchanged.
    assert_eq!(
        access_token_offline(
            "microsoft.excel",
            br#"{"access_token":"ms-access","refresh_token":"ms-refresh","client_id":"ms-client"}"#,
        )?,
        "ms-access"
    );
    Ok(())
}

#[test]
fn a_google_connection_refuses_a_microsoft_grant_before_any_send() {
    let refused = access_token_offline("google.sheets", MICROSOFT_TEST_GRANT)
        .expect_err("a Microsoft grant gives the Google connection no token");
    assert!(
        refused.to_string().contains("never sent to Google"),
        "refused before Google's token endpoint is tried: {refused}"
    );
}

/// Gmail's token step presents a stored access token as it is; a Microsoft
/// grant's is refused before any Gmail call (Muse review of #7774, F1).
#[test]
fn gmail_refuses_a_microsoft_grant_before_any_send() -> TestResult {
    let client = reqwest::blocking::Client::builder().build()?;
    let refused = gmail_authorization(&client, MICROSOFT_TEST_GRANT)
        .expect_err("a Microsoft grant gives Gmail no Authorization header");
    assert!(
        refused.to_string().contains("never sent to Google"),
        "refused before Gmail is called: {refused}"
    );
    // A Google grant's access token is still presented as it is.
    let header = gmail_authorization(
        &client,
        br#"{"access_token":"google-access","refresh_token":"google-refresh","client_id":"google-client"}"#,
    )?;
    assert_eq!(header.to_str()?, "Bearer google-access");
    Ok(())
}
