//! `oneiron seat …`: the owner's official-seat sign-in surface (OF-375).
//!
//! These commands print what the PERSON runs to sign a seat in and where
//! that seat may run. They never ask for, print, or store a vendor token:
//! the verifier flag below is hashed into a PKCE challenge on the spot and
//! the verifier itself is never written anywhere.

use std::io::{self, Read as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{SeatLoginPlanArgs, SeatRunnerPolicyArgs};
use crate::runtime::seat_login::{
    RunnerSeatPolicySettings, SeatSettings, runner_policy_surface, runner_provider_catalog,
    seat_login_surface, seat_route_catalog, siwc_authorize_request,
};

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
    ) {
        (Some(client_id), Some(redirect_uri), Some(verifier), Some(state)) => Some(
            siwc_authorize_request(
                client_id.to_owned(),
                redirect_uri.to_owned(),
                verifier,
                state.to_owned(),
                args.siwc_scope.clone(),
            )
            .map_err(anyhow::Error::msg)?,
        ),
        (None, None, None, None) => None,
        _ => anyhow::bail!(
            "Sign in with ChatGPT needs all of --siwc-client-id, --siwc-redirect-uri, --siwc-verifier, --siwc-state"
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
    let surface =
        seat_login_surface(args.mode, &settings, now, siwc.as_ref()).map_err(anyhow::Error::msg)?;
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
