//! Operator door that provisions the ACTIVE, agent-bound
//! `imessage_self_host_bridge` receiving identity a self-host bridge dogfood
//! run needs (CID-9 / ONE-1513).
//!
//! ```text
//! cargo run --example provision_imessage_identity -- <vault> <handle> <agent-ref>
//! ```
//!
//! `<agent-ref>` is the 32-hex `EntityId` of the agent to bind. That agent must
//! already exist in the vault: an absent agent fails closed instead of being
//! invented or defaulted. The record is created in `Requested` and walked
//! through the checked `Requested -> PendingFulfillment (manual) -> Active`
//! lifecycle; constructing it directly in `Active` is not permitted.
//!
//! The landed assignment key is the `(channel, receiving handle)` tuple, and
//! uniqueness is enforced on that tuple by `Vault::create_channel_identity`.
//!
//! Vaults whose embedding width differs from the server preset can be opened by
//! setting `ONEIRON_VAULT_DIMENSIONS`; every other open parameter is the
//! preset's.
//!
//! Output is limited to the minted identity ref and a non-secret confirmation
//! of channel, shape, binding, handle, and state — nothing else is printed, and
//! failures never echo the supplied handle.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    ChannelIdentityState, EntityId, Vault, VaultConfig,
};

/// Channel assignment provisioned by this door.
const CHANNEL: &str = "imessage_self_host_bridge";

/// Optional embedding-width override for opening an existing vault.
const DIMENSIONS_ENV: &str = "ONEIRON_VAULT_DIMENSIONS";

const USAGE: &str =
    "usage: cargo run --example provision_imessage_identity -- <vault> <handle> <agent-ref>";

struct Args {
    vault_path: PathBuf,
    handle: String,
    agent_ref: EntityId,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("provision_imessage_identity: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let Args {
        vault_path,
        handle,
        agent_ref,
    } = parse_args()?;
    let vault = open_vault(&vault_path)?;

    // Fail closed on an unknown agent: this door binds an existing agent or
    // provisions nothing at all.
    if vault
        .get_agent_definition(&agent_ref)
        .map_err(|err| format!("reading the supplied agent definition failed: {err}"))?
        .is_none()
    {
        return Err(format!(
            "agent {} is absent from this vault; refusing to invent an agent binding",
            agent_ref.to_hex()
        ));
    }

    let now = unix_seconds_now()?;
    let identity_ref = EntityId::now();
    let requested = ChannelIdentity::requested(
        CHANNEL,
        handle,
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityBinding::agent(agent_ref),
        now,
    );
    vault
        .create_channel_identity(&identity_ref, &requested)
        .map_err(|err| format!("creating the {CHANNEL} identity failed: {err}"))?;

    let active = fulfill(&vault, &identity_ref, now)?;
    print_confirmation(&identity_ref, &active, agent_ref);
    Ok(())
}

/// Applies exactly `Requested -> PendingFulfillment (manual) -> Active`.
fn fulfill(vault: &Vault, identity_ref: &EntityId, now: u64) -> Result<ChannelIdentity, String> {
    let pending = vault
        .transition_channel_identity(
            identity_ref,
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Manual),
            now,
            None,
        )
        .map_err(|err| format!("transition to pending_fulfillment failed: {err}"))?;
    if pending.state != ChannelIdentityState::PendingFulfillment
        || pending.pending_fulfillment != Some(ChannelIdentityFulfillment::Manual)
    {
        return Err("pending_fulfillment transition did not land the manual lane".to_owned());
    }

    let active = vault
        .transition_channel_identity(identity_ref, ChannelIdentityState::Active, None, now, None)
        .map_err(|err| format!("transition to active failed: {err}"))?;
    if active.state != ChannelIdentityState::Active {
        return Err("active transition did not land the active state".to_owned());
    }
    Ok(active)
}

fn parse_args() -> Result<Args, String> {
    let mut raw = env::args_os().skip(1);
    let vault_path = next_arg(&mut raw, "vault")?;
    let handle = utf8_arg(next_arg(&mut raw, "handle")?, "handle")?;
    let handle = handle.trim().to_owned();
    if handle.is_empty() {
        return Err(format!("<handle> must not be blank; {USAGE}"));
    }
    let agent_ref = utf8_arg(next_arg(&mut raw, "agent-ref")?, "agent-ref")?;
    if raw.next().is_some() {
        return Err(format!("too many arguments; {USAGE}"));
    }
    Ok(Args {
        vault_path: PathBuf::from(vault_path),
        handle,
        agent_ref: parse_agent_ref(&agent_ref)?,
    })
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<OsString, String> {
    let value = args
        .next()
        .ok_or_else(|| format!("missing <{name}>; {USAGE}"))?;
    if value.to_string_lossy().trim().is_empty() {
        return Err(format!("<{name}> must not be blank; {USAGE}"));
    }
    Ok(value)
}

fn utf8_arg(value: OsString, name: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| format!("<{name}> must be valid UTF-8; {USAGE}"))
}

/// Accepts only a 32-character hex `EntityId`; anything else is a malformed
/// agent ref rather than a lookup miss.
fn parse_agent_ref(raw: &str) -> Result<EntityId, String> {
    let trimmed = raw.trim();
    if trimmed.len() != 32 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "<agent-ref> must be a 32-character hex EntityId; {USAGE}"
        ));
    }
    EntityId::from_hex(trimmed).map_err(|err| format!("<agent-ref> is not a valid EntityId: {err}"))
}

fn open_vault(path: &Path) -> Result<Vault, String> {
    let mut config = VaultConfig::server();
    if let Some(raw) = env::var_os(DIMENSIONS_ENV) {
        let dimensions = raw.to_string_lossy().trim().parse::<usize>().map_err(|err| {
            format!("{DIMENSIONS_ENV} must be a positive integer number of dimensions: {err}")
        })?;
        config.dimensions = dimensions;
    }
    Vault::open(path, config).map_err(|err| format!("opening the vault at {path:?} failed: {err}"))
}

fn unix_seconds_now() -> Result<u64, String> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the unix epoch".to_owned())?;
    Ok(since_epoch.as_secs())
}

/// Prints the operator receipt recorded in the dogfood notes. No credential,
/// token, or provider secret passes through this door, so there is nothing here
/// to redact beyond the operator's own handle argument, which is echoed once.
fn print_confirmation(identity_ref: &EntityId, identity: &ChannelIdentity, agent_ref: EntityId) {
    println!("identity_ref: {}", identity_ref.to_hex());
    println!("channel: {}", identity.channel);
    println!("shape: {}", identity.shape.as_str());
    println!(
        "binding: {}:{}",
        identity.binding.scope_str(),
        agent_ref.to_hex()
    );
    println!("receiving_handle: {}", identity.address_or_handle);
    println!("state: {}", identity.state.as_str());
}
