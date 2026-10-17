//! The served Slack app and the provider URLs of the built-in channels
//! (OF-519): the manifest the owner creates the app from, the URLs each
//! built-in channel's setup shows, and the app's OAuth install. The install
//! starts at an owner door, which holds the owner's proof under one
//! single-use `state`. Slack's redirect to `/v1/hooks/slack/oauth` redeems
//! that state, trades the code for the bot token, stores it in custody under
//! the held proof and checks the connection, so the redirect itself carries
//! no authority.

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use oneiron::Vault;
use oneiron::channel_identity_provider::{
    SlackSharedPresenceAdapter, SlackSharedPresenceAdapterConfig,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{Error, SecretError};
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::skill_hub::pack_catalog::{PackSetupCheck, PackSetupView};
use rand_core::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::HostConnectionChecks;
use super::handles::SLACK_CONNECTION;
use super::webhooks::{LINE_WEBHOOK_PATH, SLACK_EVENTS_PATH, SLACK_OAUTH_PATH};
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// The built-in packs whose setups show provider URLs.
const SLACK_PACK: &str = "oneiron.slack";
const LINE_PACK: &str = "oneiron.line";
/// The fixed names the served Slack app goes by (Engine ruling 10-17).
const SLACK_APP_NAME: &str = "Oneiron";
/// The custody names of the Slack app's credentials, all read by the
/// Slack connector only.
const SLACK_EFFECTOR: &str = "connector:slack";
const SLACK_BOT_TOKEN: &str = "slack.bot_token";
const SLACK_CLIENT_ID: &str = "slack.client_id";
const SLACK_CLIENT_SECRET: &str = "slack.client_secret";
const SLACK_AUTHORIZE_URL: &str = "https://slack.com/oauth/v2/authorize";
const SLACK_OAUTH_ACCESS_URL: &str = "https://slack.com/api/oauth.v2.access";
/// How long an install link stays redeemable.
const INSTALL_TTL: Duration = Duration::from_secs(10 * 60);
/// Install links held at once; a new one pushes out the oldest.
const MAX_PENDING_INSTALLS: usize = 8;
const MAX_OAUTH_REPLY_BYTES: u64 = 64 * 1024;

/// The host's public origin from `oauth_resource_indicator`: https, with no
/// trailing slash. Slack and LINE deliver only to https URLs.
pub(crate) fn public_origin(configured: Option<&str>) -> Option<String> {
    let origin = configured?.trim().trim_end_matches('/');
    origin.starts_with("https://").then(|| origin.to_owned())
}

/// The Slack app's config at this host's origin: the one product-level app.
pub(crate) fn slack_app_config(origin: &str) -> oneiron::Result<SlackSharedPresenceAdapterConfig> {
    SlackSharedPresenceAdapterConfig::new(
        SLACK_APP_NAME,
        SLACK_APP_NAME,
        format!("{origin}{SLACK_EVENTS_PATH}"),
        vec![format!("{origin}{SLACK_OAUTH_PATH}")],
    )
}

/// The manifest the owner pastes at api.slack.com/apps. It needs no checked
/// connection: the app is made before anything can be checked.
pub(crate) fn slack_app_manifest(origin: &str) -> oneiron::Result<Value> {
    Ok(SlackSharedPresenceAdapter::new(slack_app_config(origin)?).app_manifest())
}

/// One URL the provider's console needs from the owner.
#[derive(Debug, Serialize)]
pub(crate) struct ProviderUrl {
    id: &'static str,
    /// Where it goes in the provider's console.
    label: &'static str,
    path: &'static str,
    /// The full URL; `None` while this host has no public https origin.
    url: Option<String>,
}

/// What a built-in channel's setup adds on this host: the URLs the provider
/// delivers to, and for Slack the app manifest.
#[derive(Debug, Default, Serialize)]
pub(crate) struct ProviderSetup {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    provider_urls: Vec<ProviderUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_manifest: Option<Value>,
}

impl ProviderSetup {
    pub(crate) fn for_pack(pack: &str, configured: Option<&str>) -> oneiron::Result<Self> {
        let rows: &[(&'static str, &'static str, &'static str)] = match pack {
            SLACK_PACK => &[
                (
                    "slack.events",
                    "Event Subscriptions and Interactivity Request URL",
                    SLACK_EVENTS_PATH,
                ),
                (
                    "slack.oauth_redirect",
                    "OAuth Redirect URL",
                    SLACK_OAUTH_PATH,
                ),
            ],
            LINE_PACK => &[(
                "line.webhook",
                "Messaging API Webhook URL",
                LINE_WEBHOOK_PATH,
            )],
            _ => return Ok(Self::default()),
        };
        let origin = public_origin(configured);
        let app_manifest = match (&origin, pack) {
            (Some(origin), SLACK_PACK) => Some(slack_app_manifest(origin)?),
            _ => None,
        };
        let provider_urls = rows
            .iter()
            .map(|&(id, label, path)| ProviderUrl {
                id,
                label,
                path,
                url: origin.as_ref().map(|origin| format!("{origin}{path}")),
            })
            .collect();
        Ok(Self {
            provider_urls,
            app_manifest,
        })
    }

    /// The URLs as lines for the setup's plain text.
    pub(crate) fn text(&self) -> String {
        if self.provider_urls.is_empty() {
            return String::new();
        }
        let mut text = String::from("\n\nThe provider's console needs these URLs:");
        for url in &self.provider_urls {
            text.push_str(&format!(
                "\n- {}: {}",
                url.label,
                url.url.as_deref().unwrap_or(url.path)
            ));
        }
        if self.provider_urls.iter().any(|url| url.url.is_none()) {
            text.push_str(
                "\nThis host has no public https origin yet: set oauth_resource_indicator to it, and the full URLs show here.",
            );
        }
        text
    }
}

/// What the owner opens to install the Slack app to the workspace.
#[derive(Debug, Serialize)]
pub(crate) struct SlackInstallLink {
    authorize_url: String,
    redirect_url: String,
    expires_in_secs: u64,
}

/// The installs started at the owner door and not yet redeemed.
#[derive(Default)]
pub(crate) struct SlackInstalls {
    pending: Mutex<HashMap<String, PendingInstall>>,
}

struct PendingInstall {
    /// The proof of the owner who started the install. Every write it makes
    /// revalidates it, so a slip revoked meanwhile stops the install.
    owner: AuthenticatedOwner,
    /// The setup's exact source, as the install door was asked.
    source: Option<String>,
    client_id: String,
    redirect_url: String,
    expires_at: Instant,
}

impl SlackInstalls {
    fn hold(&self, state: String, install: PendingInstall) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        pending.retain(|_, held| held.expires_at > now);
        while pending.len() >= MAX_PENDING_INSTALLS {
            let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, held)| held.expires_at)
                .map(|(state, _)| state.clone())
            else {
                break;
            };
            pending.remove(&oldest);
        }
        pending.insert(state, install);
    }

    /// Redeems one state, once.
    fn take(&self, state: &str) -> Option<PendingInstall> {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(state)
            .filter(|held| held.expires_at > Instant::now())
    }
}

/// Starts one install for the owner: the bot scopes are the ones the owner
/// allowed on the setup's permission card, the client id comes out of
/// custody, and the owner's proof waits under a fresh state for Slack's
/// redirect.
pub(crate) fn start_slack_install(
    server: &SyncServer,
    owner: AuthenticatedOwner,
    source: Option<String>,
) -> Result<SlackInstallLink, OwnerError> {
    let origin = public_origin(server.config.oauth_resource_indicator.as_deref()).ok_or_else(|| {
        OwnerError::Invalid(
            "this host has no public https origin; set oauth_resource_indicator before installing the Slack app"
                .to_owned(),
        )
    })?;
    let vault = server.vault();
    let setup = vault.pack_setup(&owner, SLACK_PACK, source.as_deref())?;
    let scopes = allowed_scopes(&setup)?;
    let client_id = client_id(vault)?;
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let state: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let redirect_url = format!("{origin}{SLACK_OAUTH_PATH}");
    let authorize_url = reqwest::Url::parse_with_params(
        SLACK_AUTHORIZE_URL,
        &[
            ("client_id", client_id.as_str()),
            ("scope", scopes.as_str()),
            ("redirect_uri", redirect_url.as_str()),
            ("state", state.as_str()),
        ],
    )
    .map_err(|error| OwnerError::Invalid(format!("the Slack install link is invalid: {error}")))?
    .to_string();
    server.builtin_handles.slack_installs.hold(
        state,
        PendingInstall {
            owner,
            source,
            client_id,
            redirect_url: redirect_url.clone(),
            expires_at: Instant::now() + INSTALL_TTL,
        },
    );
    Ok(SlackInstallLink {
        authorize_url,
        redirect_url,
        expires_in_secs: INSTALL_TTL.as_secs(),
    })
}

/// The bot scopes of the app connection's allowed permissions, in the
/// declared order: the check passes only on exactly these.
fn allowed_scopes(setup: &PackSetupView) -> Result<String, OwnerError> {
    let declared = setup
        .setup
        .connections
        .iter()
        .find(|connection| connection.id == SLACK_CONNECTION);
    let state = setup
        .connections
        .iter()
        .find(|connection| connection.id == SLACK_CONNECTION);
    let (Some(declared), Some(state)) = (declared, state) else {
        return Err(OwnerError::Invalid(format!(
            "the Slack setup declares no {SLACK_CONNECTION} connection"
        )));
    };
    let scopes: Vec<&str> = declared
        .permissions
        .iter()
        .filter(|permission| {
            state
                .permissions
                .iter()
                .any(|granted| granted.id == permission.id && granted.granted)
        })
        .filter_map(|permission| permission.scope.as_deref())
        .collect();
    if scopes.is_empty() {
        return Err(OwnerError::Invalid(
            "allow the app's permissions on the setup's permission card first".to_owned(),
        ));
    }
    Ok(scopes.join(","))
}

/// The app's client id. Public in every install link, but stored with the
/// app's other credentials so the setup holds them all.
fn client_id(vault: &Vault) -> Result<String, OwnerError> {
    let mut id = None;
    vault
        .inject_secret_at_door(SLACK_CLIENT_ID, SLACK_EFFECTOR, &mut |value: &[u8]| {
            let value = std::str::from_utf8(value)
                .map_err(|_| Error::InvalidConfig("the stored client id is not text".to_owned()))?;
            id = Some(value.trim().to_owned());
            Ok(())
        })
        .map_err(|error| {
            OwnerError::Invalid(format!(
                "store the app's Client ID as {SLACK_CLIENT_ID} first ({error})"
            ))
        })?;
    id.filter(|id| !id.is_empty())
        .ok_or_else(|| OwnerError::Invalid(format!("{SLACK_CLIENT_ID} is empty")))
}

/// Slack's redirect after the owner approves, or declines, the install.
#[derive(Debug, Deserialize)]
pub(crate) struct SlackOAuthRedirect {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `GET /v1/hooks/slack/oauth`: keyless. The state redeems the owner's proof
/// held at the install door, once; the page is plain text for the owner's
/// browser tab.
pub(crate) async fn slack_oauth(
    State(server): State<Arc<SyncServer>>,
    Query(redirect): Query<SlackOAuthRedirect>,
) -> Response {
    let Some(install) = redirect
        .state
        .as_deref()
        .and_then(|state| server.builtin_handles.slack_installs.take(state))
    else {
        return page(
            StatusCode::BAD_REQUEST,
            "This install link is unknown, used or expired. Start the Slack install again from the pack's setup."
                .to_owned(),
        );
    };
    if let Some(error) = redirect.error {
        let error: String = error
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        return page(
            StatusCode::OK,
            format!(
                "Slack did not install the app ({error}). Start the install again from the pack's setup."
            ),
        );
    }
    let Some(code) = redirect.code else {
        return page(
            StatusCode::BAD_REQUEST,
            "Slack sent no code. Start the install again from the pack's setup.".to_owned(),
        );
    };
    match tokio::task::spawn_blocking(move || finish_install(&server, &install, &code)).await {
        Ok(Ok(message)) => page(StatusCode::OK, message),
        Ok(Err(error)) => {
            tracing::warn!(%error, "Slack install did not finish");
            page(
                StatusCode::BAD_GATEWAY,
                format!("The Slack install did not finish: {error}"),
            )
        }
        Err(_) => page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The Slack install failed on this host.".to_owned(),
        ),
    }
}

fn page(status: StatusCode, text: String) -> Response {
    (status, text).into_response()
}

/// Trades the code for the bot token, stores it under the owner's proof
/// and checks the connection, which qualifies the pack once it is ready.
fn finish_install(
    server: &SyncServer,
    install: &PendingInstall,
    code: &str,
) -> oneiron::Result<String> {
    let vault = server.vault();
    let grant = exchange_code(vault, install, code)?;
    store(vault, &install.owner, SLACK_BOT_TOKEN, &grant.access_token)?;
    let checks = HostConnectionChecks::new(server)?;
    let view = vault.verify_pack_connection(
        &install.owner,
        SLACK_PACK,
        install.source.as_deref(),
        SLACK_CONNECTION,
        &checks,
    )?;
    let check = view
        .connections
        .iter()
        .find(|connection| connection.id == SLACK_CONNECTION)
        .map(|connection| &connection.check);
    Ok(match check {
        Some(PackSetupCheck::Verified { .. }) => {
            "Slack is installed and its connection check passed. You can close this tab.".to_owned()
        }
        Some(PackSetupCheck::Failed { reason, .. }) => format!(
            "Slack is installed, but the connection check failed: {reason}. Fix it in the pack's setup and check again."
        ),
        _ => "Slack is installed. Check the connection from the pack's setup.".to_owned(),
    })
}

struct SlackGrant {
    access_token: Zeroizing<String>,
}

#[derive(Deserialize)]
struct OAuthAccess {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

/// `oauth.v2.access` with the client secret read inside the credential
/// door, bound to the exact redirect URL the install link named.
fn exchange_code(
    vault: &Vault,
    install: &PendingInstall,
    code: &str,
) -> oneiron::Result<SlackGrant> {
    let invalid = |message: String| Error::InvalidConfig(message);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| invalid("the Slack OAuth client is unavailable".to_owned()))?;
    let mut reply = None;
    vault.inject_secret_at_door(
        SLACK_CLIENT_SECRET,
        SLACK_EFFECTOR,
        &mut |secret: &[u8]| {
            let secret = std::str::from_utf8(secret)
                .map_err(|_| invalid("the stored client secret is not text".to_owned()))?;
            let response = client
                .post(SLACK_OAUTH_ACCESS_URL)
                .form(&[
                    ("client_id", install.client_id.as_str()),
                    ("client_secret", secret.trim()),
                    ("code", code),
                    ("redirect_uri", install.redirect_url.as_str()),
                ])
                .send()
                .map_err(|error| {
                    invalid(format!(
                        "Slack could not be reached: {}",
                        error.without_url()
                    ))
                })?;
            let mut body = Zeroizing::new(Vec::new());
            response
                .take(MAX_OAUTH_REPLY_BYTES + 1)
                .read_to_end(&mut body)
                .map_err(|_| invalid("Slack's OAuth reply is unreadable".to_owned()))?;
            if body.len() as u64 > MAX_OAUTH_REPLY_BYTES {
                return Err(invalid("Slack's OAuth reply exceeds its bound".to_owned()));
            }
            reply = Some(body);
            Ok(())
        },
    )?;
    let body = reply.ok_or_else(|| invalid("the code exchange did not run".to_owned()))?;
    let access: OAuthAccess = serde_json::from_slice(&body)
        .map_err(|_| invalid("Slack's OAuth reply is not JSON".to_owned()))?;
    if !access.ok {
        return Err(invalid(format!(
            "Slack refused the install: {}",
            access.error.as_deref().unwrap_or("no reason given")
        )));
    }
    match (access.token_type.as_deref(), access.access_token) {
        (Some("bot"), Some(token)) if !token.is_empty() => Ok(SlackGrant {
            access_token: Zeroizing::new(token),
        }),
        _ => Err(invalid("Slack returned no bot token".to_owned())),
    }
}

/// Stores one credential for the Slack connector under the owner's proof:
/// a new record for a new name, else a rotation of the live one.
fn store(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    name: &str,
    value: &str,
) -> oneiron::Result<()> {
    let at = vault.now_recorded_at();
    let registration = OwnerSecretRegistration {
        name,
        class: CustodyClass::CustodyPortable,
        device_only: false,
        rung: CustodyTier::T0Doored,
        bindings: vec![RequestedBinding {
            effector: SLACK_EFFECTOR.to_owned(),
            tier_ceiling: None,
            scopes: vec!["read".to_owned()],
        }],
        manifest: None,
        value: value.as_bytes(),
    };
    match vault.register_secret_as_owner(owner, &registration, at) {
        Ok(_) => Ok(()),
        Err(Error::Secret(SecretError::SecretNameInUse { .. })) => vault
            .rotate_secret_as_owner(owner, name, value.as_bytes(), at)
            .map(|_| ()),
        Err(error) => Err(error),
    }
}
