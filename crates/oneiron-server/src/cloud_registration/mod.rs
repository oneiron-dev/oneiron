//! The engine's native cloud registration client (G7, FIX 5347): the owner
//! links this vault to the Oneiron cloud account the owner approves, over
//! LC cloud #97's RFC 8628 device grant, and the engine keeps the token
//! family in its own custody (`oneiron::secret_custody` cloud registration
//! slots).
//!
//! One service per open vault, used by `oneiron account` on a stopped vault
//! and by `/v1/owner/cloud-registration` on a running one. Every act is the
//! owner's: login, status, refresh and logout, nothing on a timer. Trust is
//! the operator's pins alone ([`pins`]); discovery only locates
//! ([`discovery`]); the access token is checked against the pins
//! ([`jwt`]), and only the audience's own answer, matched field for field,
//! says the registration is live.
//!
//! Refreshes are serialized: one mutex per vault here, and the vault's
//! writer lease, which this process holds. A reservation commits before the
//! refresh token leaves, and the successor commits with its generation after
//! (`refresh`). A lost or uncertain answer, `invalid_grant`, an answer the
//! pins do not verify, or a successor that did not commit means the owner
//! logs in again: no spent token is ever sent twice. Any 503 is "cloud
//! registration unavailable", its optional description shown verbatim.
//!
//! Lifecycle (L04 08:3x): `logout` stops the local binding, then tries an
//! RFC 7009 revoke; `logout --erase` is the owner's erase, every slot
//! crypto-shredded first and the revoke tried after, each result reported
//! apart. A delete keeps the tokens; switching the feature off does nothing
//! to them.

mod binding;
mod device;
mod discovery;
mod http;
mod jwt;
mod pins;
mod refresh;
mod wire;

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CloudRegistrationBinding, CloudRegistrationFence, CloudRegistrationPhase,
    CloudRegistrationTokenUse,
};
use serde::Serialize;
use zeroize::Zeroizing;

use self::device::Flows;
use self::discovery::Endpoints;
use self::http::Http;
use self::pins::{Pins, Trust};
use self::wire::{CLIENT_ID, Failure, RegistrationStatus, TokenSet};

/// The cloud registration client of one open vault.
pub(crate) struct CloudRegistration {
    trust: Trust,
    flows: Mutex<Flows>,
    /// Serializes every act that sends a slot's token, so no two refreshes
    /// of one family overlap in this process.
    family: Mutex<()>,
}

impl CloudRegistration {
    /// The client under the pins file `pins` names, read now. Pins absent or
    /// invalid leave this feature alone off, warned once.
    pub(crate) fn new(pins: Option<&Path>) -> Self {
        let trust = Trust::load(pins);
        if let (Some(_), Trust::NotConfigured(reason)) = (pins, &trust) {
            tracing::warn!(%reason, "cloud registration is not configured");
        }
        Self {
            trust,
            flows: Mutex::default(),
            family: Mutex::new(()),
        }
    }

    fn pins(&self) -> Result<&Arc<Pins>, Failure> {
        match &self.trust {
            Trust::Pinned(pins) => Ok(pins),
            Trust::NotConfigured(reason) => Err(Failure::NotConfigured(reason.clone())),
        }
    }

    fn flows(&self) -> MutexGuard<'_, Flows> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn family(&self) -> MutexGuard<'_, ()> {
        self.family.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One link, as the owner reads it: no token.
#[derive(Debug, Serialize)]
pub(crate) struct LinkView {
    slot: String,
    issuer: String,
    subject: String,
    phase: CloudRegistrationPhase,
    generation: u32,
    linked_at: u64,
    changed_at: u64,
}

impl From<&CloudRegistrationBinding> for LinkView {
    fn from(binding: &CloudRegistrationBinding) -> Self {
        Self {
            slot: binding.slot.to_hex(),
            issuer: binding.issuer.clone(),
            subject: binding.subject.clone(),
            phase: binding.phase,
            generation: binding.generation,
            linked_at: binding.linked_at,
            changed_at: binding.changed_at,
        }
    }
}

/// Where the owner's registration stands (CALLS G7_OWNER_STATUS).
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Status {
    /// The pins are absent or invalid: this feature alone is off.
    NotConfigured { reason: String },
    /// Nothing is linked under the pinned issuer.
    SignedOut,
    /// The audience answered for the verified token just now.
    Registered {
        link: LinkView,
        verified_at: u64,
        expires_at: u64,
    },
    /// Linked, its access token stopped: an explicit refresh renews it.
    NeedsRefresh { link: LinkView },
    /// The family is lost or uncertain: log in again.
    NeedsLogin { link: LinkView, reason: String },
    /// Any 503: cloud registration unavailable.
    Unavailable {
        link: Option<LinkView>,
        description: Option<String>,
    },
    /// An answer off the wire, or a refusal the client cannot act on.
    Failed {
        link: Option<LinkView>,
        reason: String,
    },
}

/// What a login's start answered.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Started {
    /// Open `verification_uri` and enter `user_code` there; poll `flow`.
    Pending {
        flow: String,
        verification_uri: String,
        user_code: String,
        expires_in: u64,
        interval: u64,
    },
    NotConfigured {
        reason: String,
    },
    Unavailable {
        description: Option<String>,
    },
    Failed {
        reason: String,
    },
}

/// What one poll of a login answered.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Polled {
    /// Not approved yet: poll again after `next_poll_in` seconds.
    Pending {
        flow: String,
        next_poll_in: u64,
        expires_in: u64,
    },
    /// Linked: `status` is its first online check; `replaced` the link it
    /// replaced, with that link's revoke.
    Linked {
        status: Status,
        replaced: Option<LinkView>,
        replaced_revoke: Option<Revoke>,
    },
    /// The approved account is another subject than the current link's,
    /// and the login did not ask to replace it: nothing was stored, and the
    /// new tokens' revoke is reported (CALLS G7_LINK_REPLACEMENT).
    ReplaceRequired {
        linked_subject: String,
        offered_subject: String,
        revoke: Revoke,
    },
    Denied,
    Expired,
    /// No flow of this owner's has that handle here.
    UnknownFlow,
    NotConfigured {
        reason: String,
    },
    /// Any 503: the flow stays, its pacing kept.
    Unavailable {
        flow: String,
        description: Option<String>,
    },
    /// The flow ended without a link: log in again.
    Failed {
        reason: String,
    },
}

/// An RFC 7009 revoke's own result, apart from the local one. An accepted
/// revoke is the issuer's empty 200: it proves the request was taken, not
/// that it knew the token.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Revoke {
    Accepted,
    Failed { reason: String },
    NotAttempted { reason: String },
}

/// What a logout did here, apart from its revoke.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum Local {
    /// Nothing was linked.
    SignedOut,
    /// The binding is stopped and the slot's value emptied; its keys stay
    /// until an erase.
    LoggedOut { link: LinkView },
    /// The owner's erase: every slot fenced and erased; `complete` false is
    /// pending, never failed.
    Erased { slots: Vec<String>, complete: bool },
}

/// What a logout answered.
#[derive(Debug, Serialize)]
pub(crate) struct LoggedOut {
    local: Local,
    revoke: Revoke,
}

/// Unix seconds now, the clock tokens are judged on.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// A token of the slot `fence` names, copied out at the T0 door for
/// `token_use` alone: the access token for `Access`, else the refresh
/// token, with when the access token stops. `None` when the fence moved or
/// the slot's value does not open here (warned).
fn held_token(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    fence: &CloudRegistrationFence,
    token_use: CloudRegistrationTokenUse,
) -> Option<(Zeroizing<String>, u64)> {
    let mut held = None;
    let sent =
        vault.send_cloud_registration_token_as_owner(owner, fence, token_use, &mut |bytes| {
            if let Some(set) = TokenSet::decode(bytes) {
                let token = match token_use {
                    CloudRegistrationTokenUse::Access => &set.access_token,
                    CloudRegistrationTokenUse::Refresh | CloudRegistrationTokenUse::Revoke => {
                        &set.refresh_token
                    }
                };
                held = Some((Zeroizing::new(token.clone()), set.access_expires_at));
            }
            Ok(())
        });
    if let Err(error) = sent {
        tracing::warn!(
            kind = ?error.kind(),
            "a cloud registration slot's token did not open"
        );
    }
    held
}

/// An RFC 7009 revoke of `token`, best effort, its own result (§5).
fn revoke(http: &Http, endpoints: &Endpoints, token: &str) -> Revoke {
    let form = [
        ("client_id", CLIENT_ID),
        ("token", token),
        ("token_type_hint", "refresh_token"),
    ];
    match http.post_form(&endpoints.revocation, &form, None) {
        Ok(reply) if reply.status == 200 => Revoke::Accepted,
        Ok(reply) => Revoke::Failed {
            reason: reply.failure("revocation endpoint").reason(),
        },
        Err(failure) => Revoke::Failed {
            reason: failure.reason(),
        },
    }
}

/// What the audience says of the verified access token now: the one live
/// proof (§7).
enum Online {
    Registered {
        verified_at: u64,
        expires_at: u64,
    },
    /// 401: the token is no longer good there.
    Stale,
    Unavailable(Option<String>),
    Failed(String),
}

impl Online {
    fn check(
        http: &Http,
        pins: &Pins,
        endpoints: &Endpoints,
        verified: &jwt::Verified,
        access_token: &str,
    ) -> Self {
        let reply = match http.get(&endpoints.audience, Some(access_token)) {
            Ok(reply) => reply,
            Err(failure) => return Self::Failed(failure.reason()),
        };
        match reply.status {
            200 => match reply.json::<RegistrationStatus>("registration status") {
                Ok(status) if jwt::matches_status(pins, verified, &status) => Self::Registered {
                    verified_at: unix_now(),
                    expires_at: status.expires_at,
                },
                Ok(_) => {
                    Self::Failed("the registration answer does not match the token".to_owned())
                }
                Err(failure) => Self::Failed(failure.reason()),
            },
            401 => Self::Stale,
            _ => match reply.failure("registration status") {
                Failure::Unavailable(description) => Self::Unavailable(description),
                failure => Self::Failed(failure.reason()),
            },
        }
    }

    /// The owner's status for `binding` from this answer.
    fn status(self, binding: &CloudRegistrationBinding) -> Status {
        let link = LinkView::from(binding);
        match self {
            Self::Registered {
                verified_at,
                expires_at,
            } => Status::Registered {
                link,
                verified_at,
                expires_at,
            },
            Self::Stale => Status::NeedsRefresh { link },
            Self::Unavailable(description) => Status::Unavailable {
                link: Some(link),
                description,
            },
            Self::Failed(reason) => Status::Failed {
                link: Some(link),
                reason,
            },
        }
    }
}

/// The owner's status for a failure before any answer was verified.
fn failed_status(failure: Failure, binding: Option<&CloudRegistrationBinding>) -> Status {
    let link = binding.map(LinkView::from);
    match failure {
        Failure::NotConfigured(reason) => Status::NotConfigured { reason },
        Failure::Unavailable(description) => Status::Unavailable { link, description },
        failure => Status::Failed {
            link,
            reason: failure.reason(),
        },
    }
}
