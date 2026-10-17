//! One handle per served built-in channel: its adapter, the provider
//! account its check bound, and the credential name its webhooks verify
//! with. A cache of what the vault already decided, never a second pack
//! authority: a webhook rechecks the pack and the check before it admits.

use std::sync::{Arc, PoisonError, RwLock};

use oneiron::Vault;
use oneiron::channel_identity_provider::{
    LINE_CHANNEL, LineOfficialAccountAdapter, SLACK_CHANNEL, SlackSharedPresenceAdapter,
};
use oneiron::skill_hub::pack_catalog::{CheckedBuiltinConnection, PackSetupSecret};

use super::slack_app::{SlackInstalls, public_origin, slack_app_config};
use crate::config::LineConfig;

/// The built-in Slack pack's connection, its request-signing secret and the
/// effector the pack declares for it (packs/builtin/slack/PACK.md).
pub(crate) const SLACK_CONNECTION: &str = "slack-app";
pub(crate) const SLACK_SIGNING_SECRET: &str = "slack.signing_secret";
pub(crate) const SLACK_SECRET_EFFECTOR: &str = "connector:slack";
/// The built-in LINE pack's connection and its webhook-signing secret.
pub(crate) const LINE_CONNECTION: &str = "line-channel";
const LINE_CHANNEL_SECRET: &str = "line.channel_secret";

/// The checked built-in channels this host serves.
#[derive(Default)]
pub(crate) struct BuiltinHandles {
    slack: RwLock<Option<Arc<SlackHandle>>>,
    line: RwLock<Option<Arc<LineHandle>>>,
    /// The Slack app installs started by the owner, awaiting Slack's redirect.
    pub(crate) slack_installs: SlackInstalls,
}

pub(crate) struct SlackHandle {
    pub(crate) adapter: SlackSharedPresenceAdapter,
    /// The workspace the connection check bound: Slack's `team_id`.
    pub(crate) team_id: String,
    pub(crate) signing_secret: PackSetupSecret,
    basis: String,
}

pub(crate) struct LineHandle {
    pub(crate) adapter: LineOfficialAccountAdapter,
    /// The bot the connection check bound: the webhook `destination`.
    pub(crate) destination: String,
    pub(crate) channel_secret: PackSetupSecret,
    basis: String,
}

impl BuiltinHandles {
    pub(crate) fn slack(&self) -> Option<Arc<SlackHandle>> {
        self.slack
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn line(&self) -> Option<Arc<LineHandle>> {
        self.line
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// One pass: every built-in channel's handle follows its pack and check.
    /// `base` is the host's public origin, the Slack app's URLs hang off it;
    /// `plan` is the LINE account's plan, as the host config names it.
    pub(crate) fn reconcile(&self, vault: &Vault, base: Option<&str>, plan: &LineConfig) {
        let slack = checked(vault, SLACK_CHANNEL, SLACK_CONNECTION).and_then(|checked| {
            let basis = basis(&checked);
            if self.slack().is_some_and(|handle| handle.basis == basis) {
                return self.slack();
            }
            slack_handle(checked, base, basis).map(Arc::new)
        });
        replace(&self.slack, slack, SLACK_CHANNEL);
        let line = checked(vault, LINE_CHANNEL, LINE_CONNECTION).and_then(|checked| {
            // A plan change rebuilds the handle, as a new check does.
            let basis = format!(
                "{}:{}:{}",
                basis(&checked),
                plan.plan.as_str(),
                plan.monthly_push_allowance()
            );
            if self.line().is_some_and(|handle| handle.basis == basis) {
                return self.line();
            }
            line_handle(checked, basis, plan).map(Arc::new)
        });
        replace(&self.line, line, LINE_CHANNEL);
    }
}

fn checked(vault: &Vault, channel: &str, connection: &str) -> Option<CheckedBuiltinConnection> {
    vault
        .checked_builtin_channel(channel, connection)
        .unwrap_or_else(|error| {
            tracing::warn!(channel, %error, "built-in channel check unreadable");
            None
        })
}

/// What a handle was built from: the source, the check and its account.
fn basis(checked: &CheckedBuiltinConnection) -> String {
    format!(
        "{}:{}:{}:{}",
        checked.content_hash,
        checked.check.basis,
        checked.check.checked_at,
        checked
            .check
            .provider_account
            .as_deref()
            .unwrap_or_default()
    )
}

fn secret(checked: &CheckedBuiltinConnection, name: &str) -> Option<PackSetupSecret> {
    checked
        .connection
        .secrets
        .iter()
        .find(|secret| secret.name == name)
        .cloned()
}

fn slack_handle(
    checked: CheckedBuiltinConnection,
    base: Option<&str>,
    basis: String,
) -> Option<SlackHandle> {
    let Some(base) = public_origin(base) else {
        tracing::info!(
            "the Slack pack is checked, but this host has no https oauth_resource_indicator for its app URLs; Slack is not served"
        );
        return None;
    };
    let Some(team_id) = checked.check.provider_account.clone() else {
        tracing::info!("the Slack check named no workspace id; check the connection again");
        return None;
    };
    let signing_secret = secret(&checked, SLACK_SIGNING_SECRET)?;
    let config = slack_app_config(&base)
        .map_err(
            |error| tracing::info!(%error, "the Slack app config is invalid; Slack is not served"),
        )
        .ok()?;
    Some(SlackHandle {
        adapter: SlackSharedPresenceAdapter::new(config),
        team_id,
        signing_secret,
        basis,
    })
}

fn line_handle(
    checked: CheckedBuiltinConnection,
    basis: String,
    plan: &LineConfig,
) -> Option<LineHandle> {
    let Some(destination) = checked.check.provider_account.clone() else {
        tracing::info!("the LINE check named no bot user id; check the connection again");
        return None;
    };
    let channel_secret = secret(&checked, LINE_CHANNEL_SECRET)?;
    // The plan the host's `[line]` row names; a free account when it names none.
    let config = plan
        .adapter_config(destination.clone())
        .map_err(|error| {
            tracing::info!(%error, "the LINE bot id or plan is invalid; LINE is not served")
        })
        .ok()?;
    Some(LineHandle {
        adapter: LineOfficialAccountAdapter::new(config),
        destination,
        channel_secret,
        basis,
    })
}

fn replace<T>(slot: &RwLock<Option<Arc<T>>>, next: Option<Arc<T>>, channel: &str) {
    let mut slot = slot.write().unwrap_or_else(PoisonError::into_inner);
    match (slot.is_some(), next.is_some()) {
        (false, true) => tracing::info!(channel, "built-in channel served"),
        (true, false) => tracing::info!(channel, "built-in channel no longer served"),
        _ => {}
    }
    *slot = next;
}
