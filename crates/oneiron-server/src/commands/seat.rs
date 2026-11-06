//! `oneiron seat …`: the owner's official-seat sign-in surface (OF-375).
//!
//! The plan commands print what the PERSON runs to sign a seat in and where
//! that seat may run. Their verifier flag is hashed into a PKCE challenge;
//! the verifier itself is never written anywhere. The explicit SIWC login
//! command saves verified credentials only in the person's protected local
//! file. No command prints a vendor token.

use std::io::{self, Read as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{SeatLoginPlanArgs, SeatRunnerPolicyArgs};
use crate::runtime::seat_login::{
    RunnerSeatPolicySettings, SeatSettings, runner_policy_surface, runner_provider_catalog,
    seat_login_surface, seat_route_catalog, siwc_authorize_request,
};

pub async fn seat_siwc_login(args: crate::cli::SiwcLoginArgs) -> anyhow::Result<()> {
    let enabled =
        crate::runtime::seat_login::siwc::login(crate::runtime::seat_login::siwc::LoginOptions {
            credential_file: args.credential_file,
            host_id_file: args.host_id_file,
            callback_uri: args.callback_uri,
            agent_name: args.agent_name,
            timeout: std::time::Duration::from_secs(args.timeout_secs),
        })
        .await?;
    let stdout = io::stdout();
    writeln!(
        stdout.lock(),
        "Sign-in saved locally; ChatGPT plan use granted: {enabled}"
    )?;
    Ok(())
}

pub fn seat_siwc_clear(args: crate::cli::SiwcCredentialArgs) -> anyhow::Result<()> {
    let result = crate::runtime::seat_login::siwc::clear(args.credential_file)?;
    print_sign_out(result)
}

pub async fn seat_siwc_revoke(args: crate::cli::SiwcRevokeArgs) -> anyhow::Result<()> {
    let result =
        crate::runtime::seat_login::siwc::revoke(crate::runtime::seat_login::siwc::RevokeOptions {
            credential_file: args.credential_file,
            retries: args.retries,
            backoff: std::time::Duration::from_millis(args.backoff_ms),
            timeout: std::time::Duration::from_secs(args.timeout_secs),
        })
        .await?;
    print_sign_out(result)
}

fn print_sign_out(result: crate::runtime::seat_login::siwc::SignOut) -> anyhow::Result<()> {
    use crate::runtime::seat_login::siwc::SignOut;
    let message = match result {
        SignOut::NoLocalRecord => "No local SIWC record; remote revocation was not confirmed.",
        SignOut::LocalOnly => "Local SIWC tokens cleared; remote grant was not revoked.",
        SignOut::Revoked => "SIWC session revocation confirmed; local tokens cleared.",
        SignOut::RevocationUnconfirmed => {
            "Local SIWC tokens cleared; remote revocation unconfirmed. Disconnect the app in ChatGPT Settings."
        }
    };
    writeln!(io::stdout().lock(), "{message}")?;
    Ok(())
}

pub fn seat_routes() -> anyhow::Result<()> {
    print_json(&seat_route_catalog())
}

pub fn seat_runners() -> anyhow::Result<()> {
    print_json(&runner_provider_catalog())
}

pub fn seat_runner_policy(args: SeatRunnerPolicyArgs) -> anyhow::Result<()> {
    let raw = if args.settings.to_str() == Some("-") {
        let mut raw = String::new();
        io::stdin().lock().read_to_string(&mut raw)?;
        raw
    } else {
        std::fs::read_to_string(&args.settings)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", args.settings.display()))?
    };
    let settings: RunnerSeatPolicySettings =
        serde_json::from_str(&raw).map_err(|error| anyhow::anyhow!("runner policy: {error}"))?;
    let surface = runner_policy_surface(&settings).map_err(anyhow::Error::msg)?;
    print_json(&surface)
}

pub fn seat_login_plan(args: SeatLoginPlanArgs) -> anyhow::Result<()> {
    let siwc = match (
        args.siwc_client_id.as_deref(),
        args.siwc_redirect_uri.as_deref(),
        args.siwc_verifier.as_deref(),
        args.siwc_state.as_deref(),
        args.siwc_nonce.as_deref(),
        args.siwc_agent_host_id.as_deref(),
    ) {
        (
            Some(client_id),
            Some(redirect_uri),
            Some(verifier),
            Some(state),
            Some(nonce),
            Some(host_id),
        ) => Some(
            siwc_authorize_request(
                client_id.to_owned(),
                redirect_uri.to_owned(),
                verifier,
                state.to_owned(),
                nonce.to_owned(),
                host_id.to_owned(),
                args.siwc_agent_name_hint.clone(),
                args.siwc_scope.clone(),
            )
            .map_err(anyhow::Error::msg)?,
        ),
        (None, None, None, None, None, None) => None,
        _ => anyhow::bail!(
            "Sign in with ChatGPT needs all of --siwc-client-id, --siwc-redirect-uri, --siwc-verifier, --siwc-state, --siwc-nonce, --siwc-agent-host-id"
        ),
    };
    let settings = SeatSettings {
        route: args.route.clone(),
        account_ref: args.account.clone(),
        machine_ref: args.machine.clone(),
        login_store_ref: args.login_store.clone(),
        credential_handle: args.credential_handle.clone(),
        unmodified_binary: !args.modified_binary,
        anthropic_agent_sdk_approved: args.anthropic_sdk_approved,
        openai_hosted_plan_approved: args.openai_hosted_approved,
        dry_fallback: args.dry.clone(),
        overdraft_cap_units: args.overdraft_cap,
        plan_percent_used: args.plan_percent_used,
        plan_resets_at: args.plan_resets_at,
    };
    let now = if args.now > 0 {
        args.now
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    };
    // The runtime's actual hosting posture judges the login, apart from its
    // inference mode (FIX 9533).
    let surface = seat_login_surface(args.hosting_posture(), &settings, now, siwc.as_ref())
        .map_err(anyhow::Error::msg)?;
    print_json(&surface)
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let rendered = serde_json::to_string_pretty(value)?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match writeln!(stdout, "{rendered}") {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}
