//! The owner's explicit refresh (CALLS G7_REFRESH_TRIGGER): one rotation of
//! the token family, serialized, durable on both sides of its one send.
//!
//! Under the family mutex and this process's writer lease, the link is
//! reserved (`InFlight`, committed), the refresh token leaves at the T0 door
//! once, and a verified successor replaces it with its generation in one
//! commit. Nothing is ever sent twice: a lost answer, `invalid_grant`, an
//! answer off the wire or the pins, a changed subject, or a successor that
//! did not commit stops the link at `NeedsLogin`, and a successor that
//! cannot be kept is revoked. A 503 leaves the reservation standing, its
//! outcome uncertain: the next act reads it as needing a login.

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CloudRegistrationBinding, CloudRegistrationPhase, CloudRegistrationTokenUse,
};

use super::discovery::{Endpoints, discover};
use super::http::{Http, Reply};
use super::jwt;
use super::pins::Pins;
use super::wire::{CLIENT_ID, Failure, REFRESH_GRANT, TokenReply, TokenSet};
use super::{CloudRegistration, LinkView, Online, Status, failed_status, revoke, unix_now};

impl CloudRegistration {
    /// Refreshes the owner's link once, then checks it online.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub(crate) fn refresh(
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
            return Ok(Status::SignedOut);
        };
        if binding.phase != CloudRegistrationPhase::Linked {
            return Ok(Status::NeedsLogin {
                link: LinkView::from(&binding),
                reason: "the token family is lost or its last refresh is uncertain".to_owned(),
            });
        }
        if !vault
            .writer_lease()
            .is_some_and(oneiron::VaultWriterLease::held_by_current_process)
        {
            return Ok(Status::Failed {
                link: Some(LinkView::from(&binding)),
                reason: "this process does not hold the vault's writer lease".to_owned(),
            });
        }
        let (http, endpoints) = match Http::new()
            .and_then(|http| discover(&http, pins).map(|endpoints| (http, endpoints)))
        {
            Ok(found) => found,
            Err(failure) => return Ok(failed_status(failure, Some(&binding))),
        };
        let fence = binding.fence();
        let at = vault.now_recorded_at();
        let Some(reserved) =
            vault.reserve_cloud_registration_refresh_as_owner(owner, &fence, at)?
        else {
            return Ok(moved(&binding));
        };
        let mut answer = None;
        let sent = vault.send_cloud_registration_token_as_owner(
            owner,
            &fence,
            CloudRegistrationTokenUse::Refresh,
            &mut |bytes| {
                answer = Some(match TokenSet::decode(bytes) {
                    Some(set) => {
                        let form = [
                            ("grant_type", REFRESH_GRANT),
                            ("refresh_token", set.refresh_token.as_str()),
                            ("client_id", CLIENT_ID),
                            ("resource", pins.audience.as_str()),
                        ];
                        http.post_form(&endpoints.token, &form, None)
                    }
                    None => Err(Failure::OffWire(
                        "the slot does not hold a token set".to_owned(),
                    )),
                });
                Ok(())
            },
        );
        let answer = match sent {
            Ok(Some(_)) => answer.unwrap_or(Err(Failure::Lost)),
            Ok(None) => return Ok(moved(&binding)),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a cloud registration slot's refresh token did not open"
                );
                Err(Failure::OffWire(
                    "the slot's token does not open here".to_owned(),
                ))
            }
        };
        let rotation = Rotation {
            vault,
            owner,
            pins,
            http: &http,
            endpoints: &endpoints,
            reserved: &reserved,
        };
        rotation.settle(answer)
    }
}

/// The owner's status when the link moved between its read and its act: an
/// erase, a logout or another login reached it first.
fn moved(binding: &CloudRegistrationBinding) -> Status {
    Status::Failed {
        link: Some(LinkView::from(binding)),
        reason: "the link changed meanwhile; read its status again".to_owned(),
    }
}

/// One reserved refresh, settling its answer.
struct Rotation<'a> {
    vault: &'a Vault,
    owner: &'a AuthenticatedOwner,
    pins: &'a Pins,
    http: &'a Http,
    endpoints: &'a Endpoints,
    reserved: &'a CloudRegistrationBinding,
}

impl Rotation<'_> {
    fn settle(&self, answer: Result<Reply, Failure>) -> oneiron::Result<Status> {
        let reply = match answer {
            Ok(reply) => reply,
            Err(failure) => return self.needs_login(failure.reason()),
        };
        if reply.status != 200 {
            return match reply.failure("token endpoint") {
                // Uncertain, never replayed: the reservation stands.
                Failure::Unavailable(description) => Ok(Status::Unavailable {
                    link: Some(LinkView::from(self.reserved)),
                    description,
                }),
                failure => self.needs_login(failure.reason()),
            };
        }
        let tokens = match reply.json::<TokenReply>("token") {
            Ok(tokens) => tokens,
            Err(failure) => return self.needs_login(failure.reason()),
        };
        if !tokens.on_wire() {
            return self.unkept(&tokens, "the token answer is not the wire's shape");
        }
        let verified = match jwt::verify(self.pins, &tokens.access_token, unix_now()) {
            Ok(verified) => verified,
            Err(failure) => return self.unkept(&tokens, &failure.reason()),
        };
        if verified.subject != self.reserved.subject {
            return self.unkept(
                &tokens,
                "the cloud subject changed (its owner revision moved); log in again",
            );
        }
        let set = match TokenSet::of(&tokens, verified.expires_at).encode() {
            Ok(set) => set,
            Err(failure) => return self.unkept(&tokens, &failure.reason()),
        };
        let at = self.vault.now_recorded_at();
        let fence = self.reserved.fence();
        let replaced = match self
            .vault
            .replace_cloud_registration_tokens_as_owner(self.owner, &fence, &set, at)
        {
            Ok(replaced) => replaced,
            Err(error) => {
                let _ = revoke(self.http, self.endpoints, &tokens.refresh_token);
                self.stop();
                return Err(error);
            }
        };
        let Some(binding) = replaced else {
            let _ = revoke(self.http, self.endpoints, &tokens.refresh_token);
            return Ok(moved(self.reserved));
        };
        Ok(Online::check(
            self.http,
            self.pins,
            self.endpoints,
            &verified,
            &tokens.access_token,
        )
        .status(&binding))
    }

    /// A successor the link cannot keep: revoked, best effort, and the link
    /// stopped at `NeedsLogin`.
    fn unkept(&self, tokens: &TokenReply, reason: &str) -> oneiron::Result<Status> {
        let _ = revoke(self.http, self.endpoints, &tokens.refresh_token);
        self.needs_login(reason.to_owned())
    }

    /// Stops the reserved link at `NeedsLogin`, for `reason`.
    fn needs_login(&self, reason: String) -> oneiron::Result<Status> {
        let at = self.vault.now_recorded_at();
        let stopped = self.vault.retire_cloud_registration_as_owner(
            self.owner,
            &self.reserved.fence(),
            CloudRegistrationPhase::NeedsLogin,
            at,
        )?;
        let link = LinkView::from(stopped.as_ref().unwrap_or(self.reserved));
        Ok(Status::NeedsLogin { link, reason })
    }

    /// [`Self::needs_login`] on a path already failing: its own fault is
    /// warned, and the reservation stands, read as needing a login.
    fn stop(&self) {
        if let Err(error) = self.needs_login(String::new()) {
            tracing::warn!(
                kind = ?error.kind(),
                "a cloud registration link was not stopped after its successor failed to commit"
            );
        }
    }
}
