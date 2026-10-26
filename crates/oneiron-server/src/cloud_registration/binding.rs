//! Login, status and logout: the device flow that ends in the owner's
//! explicit link, the read of where it stands, and the stop or erase of it.
//!
//! A login maps the verified cloud subject (`cp-owner:<account>:<revision>`)
//! to the local owner whose proven request started it, by that act alone,
//! never by comparing names (CALLS G7_LINK_REPLACEMENT for another subject
//! over a current link). Status reads; it never rotates a family. Logout
//! copies the refresh token out at the door, stops the binding here, then
//! tries the revoke with that copy; `erase` erases every slot first.

use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CloudRegistrationLink, CloudRegistrationLinked, CloudRegistrationPhase,
    CloudRegistrationTokenUse,
};
use zeroize::Zeroizing;

use super::device::Flow;
use super::discovery::{Endpoints, discover};
use super::http::Http;
use super::jwt;
use super::pins::Pins;
use super::wire::{
    CLIENT_ID, DEVICE_GRANT, DeviceAuthorization, Failure, SCOPE, TokenReply, TokenSet,
};
use super::{
    CloudRegistration, LinkView, Local, LoggedOut, Online, Polled, Revoke, Started, Status,
    failed_status, held_token, revoke, unix_now,
};

/// The longest code lifetime and the shortest interval the client takes
/// (§2): a start that answers a longer deadline or a faster pace is off the
/// wire.
const MAX_CODE_LIFETIME_SECS: u64 = 600;
const MIN_INTERVAL_SECS: u64 = 5;

fn whole_secs(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// Whether `uri` is a verification URI the owner may be shown: https, with
/// no user and no fragment (§1).
fn shown_uri(uri: &str) -> bool {
    reqwest::Url::parse(uri).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

impl CloudRegistration {
    /// Starts a login for `owner`: discovery, then the device authorization.
    /// The owner is shown the verification URI and the user code apart,
    /// never a URL that carries the code (§2). `replace` lets its link
    /// replace a current link to another subject. A logout or an erase
    /// while its request runs ends it unheld.
    ///
    /// # Errors
    /// The owner proof's own.
    pub(crate) fn start(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        replace: bool,
    ) -> oneiron::Result<Started> {
        let pins = match self.pins() {
            Ok(pins) => pins,
            Err(failure) => return Ok(started_failure(failure)),
        };
        let actor = owner.actor_for_read(vault)?;
        let epoch = self.flows().epoch();
        let started = Instant::now();
        let begun = Http::new().and_then(|http| {
            let endpoints = discover(&http, pins)?;
            let form = [
                ("client_id", CLIENT_ID),
                ("scope", SCOPE),
                ("resource", pins.audience.as_str()),
            ];
            let reply = http.post_form(&endpoints.device_authorization, &form, None)?;
            if reply.status != 200 {
                return Err(reply.failure("device authorization endpoint"));
            }
            let mut answer: DeviceAuthorization = reply.json("device authorization")?;
            let on_wire = answer.device_code.starts_with("odc_")
                && !answer.user_code.is_empty()
                && shown_uri(&answer.verification_uri)
                && (1..=MAX_CODE_LIFETIME_SECS).contains(&answer.expires_in)
                && answer.interval >= MIN_INTERVAL_SECS;
            if !on_wire {
                return Err(Failure::OffWire(
                    "the device authorization is not the wire's shape".to_owned(),
                ));
            }
            let device_code = Zeroizing::new(std::mem::take(&mut answer.device_code));
            Ok((endpoints, answer, device_code))
        });
        let (endpoints, answer, device_code) = match begun {
            Ok(begun) => begun,
            Err(failure) => return Ok(started_failure(failure)),
        };
        let flow = Flow::new(
            actor,
            replace,
            endpoints,
            device_code,
            started,
            answer.expires_in,
            answer.interval,
        );
        let handle = {
            let mut flows = self.flows();
            flows.expire(Instant::now());
            flows.hold(flow, epoch)
        };
        let Some(handle) = handle else {
            return Ok(Started::Cancelled);
        };
        Ok(Started::Pending {
            flow: handle,
            verification_uri: answer.verification_uri.clone(),
            user_code: answer.user_code.clone(),
            expires_in: answer.expires_in,
            interval: answer.interval,
        })
    }

    /// One poll of the login `handle` names, by a fresh request of the owner
    /// who started it: at most one token request, sent only when due. A
    /// logout or an erase while its request runs ends the flow unlinked.
    ///
    /// # Errors
    /// The owner proof's own; the vault's refusal of the link.
    pub(crate) fn poll(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        handle: &str,
    ) -> oneiron::Result<Polled> {
        let pins = match self.pins() {
            Ok(pins) => pins,
            Err(failure) => {
                return Ok(Polled::NotConfigured {
                    reason: failure.reason(),
                });
            }
        };
        let actor = owner.actor_for_read(vault)?;
        let now = Instant::now();
        let (taken, epoch) = {
            let mut flows = self.flows();
            let taken = flows.take(handle, &actor);
            flows.expire(now);
            (taken, flows.epoch())
        };
        let Some(mut flow) = taken else {
            return Ok(Polled::UnknownFlow);
        };
        if flow.left(now).is_zero() {
            return Ok(Polled::Expired);
        }
        let wait = flow.wait(now);
        if !wait.is_zero() {
            let pending = Polled::Pending {
                flow: handle.to_owned(),
                next_poll_in: whole_secs(wait),
                expires_in: whole_secs(flow.left(now)),
            };
            if !self.flows().put_back(handle.to_owned(), flow, epoch) {
                return Ok(Polled::Cancelled { revoke: None });
            }
            return Ok(pending);
        }
        let http = match Http::new() {
            Ok(http) => http,
            Err(failure) => {
                self.flows().put_back(handle.to_owned(), flow, epoch);
                return Ok(Polled::Failed {
                    reason: failure.reason(),
                });
            }
        };
        let sent = Instant::now();
        let form = [
            ("grant_type", DEVICE_GRANT),
            ("device_code", flow.device_code.as_str()),
            ("client_id", CLIENT_ID),
            ("resource", pins.audience.as_str()),
        ];
        let reply = match http.post_form(&flow.endpoints.token, &form, Some(flow.left(sent))) {
            Ok(reply) => reply,
            // A lost answer may have been the one success: never polled again.
            Err(failure) => {
                return Ok(Polled::Failed {
                    reason: failure.reason(),
                });
            }
        };
        if reply.status == 200 {
            let tokens = match reply.json::<TokenReply>("token") {
                Ok(tokens) => tokens,
                Err(failure) => {
                    return Ok(Polled::Failed {
                        reason: failure.reason(),
                    });
                }
            };
            // Under the family guard a logout or an erase advances the
            // epoch, so none can land between this read and the link.
            let _family = self.family();
            if self.flows().epoch() != epoch {
                return Ok(Polled::Cancelled {
                    revoke: Some(revoke(&http, &flow.endpoints, &tokens.refresh_token)),
                });
            }
            return self.link(vault, owner, pins, &http, &flow, &tokens);
        }
        let pending = |flow: &Flow| Polled::Pending {
            flow: handle.to_owned(),
            next_poll_in: whole_secs(flow.wait(Instant::now())),
            expires_in: whole_secs(flow.left(Instant::now())),
        };
        let polled = match reply.failure("token endpoint") {
            Failure::Refused(code) if code == "authorization_pending" => {
                flow.polled(sent);
                pending(&flow)
            }
            Failure::Refused(code) if code == "slow_down" => {
                flow.slow_down(sent);
                pending(&flow)
            }
            Failure::Refused(code) if code == "access_denied" => return Ok(Polled::Denied),
            Failure::Refused(code) if code == "expired_token" => return Ok(Polled::Expired),
            Failure::Unavailable(description) => {
                flow.polled(sent);
                Polled::Unavailable {
                    flow: handle.to_owned(),
                    description,
                }
            }
            failure => {
                return Ok(Polled::Failed {
                    reason: failure.reason(),
                });
            }
        };
        if !self.flows().put_back(handle.to_owned(), flow, epoch) {
            return Ok(Polled::Cancelled { revoke: None });
        }
        Ok(polled)
    }

    /// The approved login's link, under the family guard its caller holds:
    /// the token reply verified against the pins, then the owner's link
    /// committed with it; only then is it reported, with its first online
    /// check. Tokens that cannot be kept are revoked.
    fn link(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        pins: &Pins,
        http: &Http,
        flow: &Flow,
        tokens: &TokenReply,
    ) -> oneiron::Result<Polled> {
        let endpoints = &flow.endpoints;
        let unkept = |reason: String| {
            let _ = revoke(http, endpoints, &tokens.refresh_token);
            Polled::Failed { reason }
        };
        if !tokens.on_wire() {
            return Ok(unkept(
                "the token answer is not the wire's shape".to_owned(),
            ));
        }
        let verified = match jwt::verify(pins, &tokens.access_token, unix_now()) {
            Ok(verified) => verified,
            Err(failure) => return Ok(unkept(failure.reason())),
        };
        let set = match TokenSet::of(tokens, verified.expires_at).encode() {
            Ok(set) => set,
            Err(failure) => return Ok(unkept(failure.reason())),
        };
        // The current link's refresh token, copied out before the link
        // replaces it, so its family can be revoked after.
        let current = vault.cloud_registration_as_owner(owner, &pins.issuer)?;
        let replaced_token = current
            .as_ref()
            .filter(|current| current.subject == verified.subject || flow.replace)
            .filter(|current| {
                matches!(
                    current.phase,
                    CloudRegistrationPhase::Linked | CloudRegistrationPhase::InFlight
                )
            })
            .and_then(|current| {
                held_token(
                    vault,
                    owner,
                    &current.fence(),
                    CloudRegistrationTokenUse::Revoke,
                )
            });
        let link = CloudRegistrationLink {
            issuer: &pins.issuer,
            audience: &pins.audience,
            subject: &verified.subject,
        };
        let at = vault.now_recorded_at();
        let linked =
            match vault.link_cloud_registration_as_owner(owner, &link, &set, flow.replace, at) {
                Ok(linked) => linked,
                Err(error) => {
                    let _ = revoke(http, endpoints, &tokens.refresh_token);
                    return Err(error);
                }
            };
        match linked {
            CloudRegistrationLinked::ReplaceRequired { current } => Ok(Polled::ReplaceRequired {
                linked_subject: current.subject,
                offered_subject: verified.subject,
                revoke: revoke(http, endpoints, &tokens.refresh_token),
            }),
            CloudRegistrationLinked::Linked { binding, replaced } => {
                let replaced_revoke = replaced.as_ref().map(|_| match &replaced_token {
                    Some((token, _)) => revoke(http, endpoints, token),
                    None => Revoke::NotAttempted {
                        reason: "the replaced link held no token to revoke".to_owned(),
                    },
                });
                let status = Online::check(http, pins, endpoints, &verified, &tokens.access_token)
                    .status(&binding);
                Ok(Polled::Linked {
                    status,
                    replaced: replaced.as_ref().map(LinkView::from),
                    replaced_revoke,
                })
            }
        }
    }

    /// Where the owner's registration stands: the durable link, and the
    /// audience's answer for its access token while that token is usable;
    /// with no link, an erase whose slots are still kept `Erasing`.
    /// It reads: it never refreshes or rotates.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub(crate) fn status(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
    ) -> oneiron::Result<Status> {
        let pins = match self.pins() {
            Ok(pins) => pins,
            Err(failure) => return Ok(failed_status(failure, None)),
        };
        let _family = self.family();
        let Some(binding) = vault.cloud_registration_as_owner(owner, &pins.issuer)? else {
            let Some(erasing) = vault.cloud_registration_erasing_as_owner(owner, &pins.issuer)?
            else {
                return Ok(Status::SignedOut);
            };
            let slots = erasing
                .slots
                .iter()
                .map(oneiron::EntityId::to_hex)
                .collect();
            return Ok(Status::Erasing {
                slots,
                complete: erasing.complete,
            });
        };
        let link = LinkView::from(&binding);
        match binding.phase {
            CloudRegistrationPhase::Linked => {}
            CloudRegistrationPhase::InFlight => {
                return Ok(Status::NeedsLogin {
                    link,
                    reason: "a refresh's outcome is uncertain".to_owned(),
                });
            }
            _ => {
                return Ok(Status::NeedsLogin {
                    link,
                    reason: "the token family is lost".to_owned(),
                });
            }
        }
        let Some((access_token, expires_at)) = held_token(
            vault,
            owner,
            &binding.fence(),
            CloudRegistrationTokenUse::Access,
        ) else {
            return Ok(Status::NeedsLogin {
                link,
                reason: "the slot's token does not open here".to_owned(),
            });
        };
        let now = unix_now();
        if expires_at <= now {
            return Ok(Status::NeedsRefresh { link });
        }
        let verified = match jwt::verify(pins, &access_token, now) {
            Ok(verified) if verified.subject == binding.subject => verified,
            Ok(_) | Err(_) => return Ok(Status::NeedsRefresh { link }),
        };
        let checked = Http::new().and_then(|http| {
            let endpoints = discover(&http, pins)?;
            Ok(Online::check(
                &http,
                pins,
                &endpoints,
                &verified,
                &access_token,
            ))
        });
        Ok(match checked {
            Ok(online) => online.status(&binding),
            Err(failure) => failed_status(failure, Some(&binding)),
        })
    }

    /// Stops the owner's link here, then tries the RFC 7009 revoke with a
    /// copy of its refresh token taken first; with `erase`, the owner's
    /// erase: every slot the owner linked fenced and erased, under every
    /// issuer when no pins name one. Pending logins of this owner end, and
    /// so does every start or poll in flight: the cancel epoch advances
    /// under the family guard, before any of this.
    ///
    /// # Errors
    /// The owner proof's own; storage faults; a legal hold on a slot.
    pub(crate) fn logout(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        erase: bool,
    ) -> oneiron::Result<LoggedOut> {
        let actor = owner.actor_for_read(vault)?;
        let _family = self.family();
        self.flows().cancel(&actor);
        let pins = self.pins().ok();
        let binding = match pins {
            Some(pins) => vault.cloud_registration_as_owner(owner, &pins.issuer)?,
            None => None,
        };
        let mut sender: Result<(Http, Endpoints, Zeroizing<String>), String> =
            Err("nothing linked here holds a token".to_owned());
        if let (Some(pins), Some(binding)) = (pins, &binding) {
            sender = if matches!(
                binding.phase,
                CloudRegistrationPhase::Linked | CloudRegistrationPhase::InFlight
            ) {
                Http::new()
                    .and_then(|http| discover(&http, pins).map(|endpoints| (http, endpoints)))
                    .map_err(|failure| failure.reason())
                    .and_then(|(http, endpoints)| {
                        held_token(
                            vault,
                            owner,
                            &binding.fence(),
                            CloudRegistrationTokenUse::Revoke,
                        )
                        .map(|(token, _)| (http, endpoints, token))
                        .ok_or_else(|| "the slot's token does not open here".to_owned())
                    })
            } else {
                Err("the link's token is already gone".to_owned())
            };
        }
        if pins.is_none() {
            sender = Err("cloud registration is not configured".to_owned());
        }
        let at = vault.now_recorded_at();
        let local = if erase {
            let issuer = pins.map(|pins| pins.issuer.as_str());
            let erased = vault.erase_cloud_registration_as_owner(owner, issuer, at)?;
            Local::Erased {
                slots: erased.slots.iter().map(oneiron::EntityId::to_hex).collect(),
                complete: erased.complete,
            }
        } else {
            match &binding {
                Some(binding) => vault
                    .retire_cloud_registration_as_owner(
                        owner,
                        &binding.fence(),
                        CloudRegistrationPhase::LoggedOut,
                        at,
                    )?
                    .map_or(Local::SignedOut, |stopped| Local::LoggedOut {
                        link: LinkView::from(&stopped),
                    }),
                None => Local::SignedOut,
            }
        };
        let revoke = match sender {
            Ok((http, endpoints, token)) => revoke(&http, &endpoints, &token),
            Err(reason) => Revoke::NotAttempted { reason },
        };
        Ok(LoggedOut { local, revoke })
    }
}

fn started_failure(failure: Failure) -> Started {
    match failure {
        Failure::NotConfigured(reason) => Started::NotConfigured { reason },
        Failure::Unavailable(description) => Started::Unavailable { description },
        failure => Started::Failed {
            reason: failure.reason(),
        },
    }
}
