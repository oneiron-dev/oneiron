//! `self.use`'s own provider checks (OF-560, FIX 4491, FIX 7647): the same
//! read-only provider call a pack setup check makes, with what comes back
//! cleared of the credential inside the credential door, with the very
//! bytes that door released, before any of it leaves. A pack setup check
//! keeps [`PackConnectionVerifier::verify`](super::PackConnectionVerifier::verify).

use super::{
    PackConnectionCheck, PackConnectionEvidence, ProviderConnectionChecks, evidence_of,
    provider_call,
};
use crate::error::Result;
use crate::secret_custody::SentPresentation;
use crate::secret_lease::{SecretGrantRef, SecretGrantTarget};
use crate::vault::Vault;

/// A check's answer, or why it failed.
type Checked = std::result::Result<PackConnectionEvidence, String>;

impl ProviderConnectionChecks {
    /// [`PackConnectionVerifier::verify`](super::PackConnectionVerifier::verify)
    /// for a `self.use` of the connection's credential (FIX 7647): the same
    /// door, call and reading, and every text in the answer or the failure
    /// cleared by `scrub` with the SAME value inside the door, before it
    /// leaves; beside the record the door resolved and the generation it
    /// released, when it released one. A door that refuses sends nothing
    /// and answers with its refusal, as `verify` does.
    pub(crate) fn verify_cleared(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
        scrub: &dyn Fn(&mut String, &[u8]),
    ) -> (Checked, Option<SentPresentation>) {
        let (method, url) = match provider_call(check.check) {
            Ok(call) => call,
            Err(failure) => return (Err(failure), None),
        };
        let Some(secret) = check.secrets.first() else {
            return (
                Err("the connection names no credential to check".to_owned()),
                None,
            );
        };
        let mut answer = None;
        let door = vault.inject_secret_at_door_resolved(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                answer = Some(self.cleared_check(check.check, &method, url, value, scrub));
                Ok(())
            },
        );
        match door {
            Ok((custody, receipt)) => (
                answer.unwrap_or_else(|| Err("the check did not run".to_owned())),
                Some(SentPresentation::cleared(custody, receipt.value_generation)),
            ),
            Err(error) => (Err(error.to_string()), None),
        }
    }

    /// [`PackConnectionVerifier::verify`](super::PackConnectionVerifier::verify)
    /// for a credential a secret grant holds (FIX 4491): the grant is
    /// redeemed for `target` at the real send
    /// ([`Vault::redeem_secret_grant_at_door`], which counts that one send
    /// and refuses a grant the record rotated past since it was admitted),
    /// and the reply is read, and every text in the answer or the failure
    /// cleared by `scrub`, with the SAME value inside the door, before it
    /// leaves; beside the generation the redemption released, `None` when
    /// it redeemed nothing (FIX 7647). The outer error is the redemption's
    /// own refusal: nothing was sent. A connector call redeems its grant at
    /// each send the same way.
    pub(crate) fn verify_granted(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
        grant: &SecretGrantRef,
        target: &SecretGrantTarget,
        scrub: &dyn Fn(&mut String, &[u8]),
    ) -> Result<(Checked, Option<u32>)> {
        let (method, url) = match provider_call(check.check) {
            Ok(call) => call,
            Err(failure) => return Ok((Err(failure), None)),
        };
        let mut answer = None;
        let redeemed =
            vault.redeem_secret_grant_at_door(grant, target, &mut |value: &[u8]| {
                answer = Some(self.cleared_check(check.check, &method, url, value, scrub));
                Ok(())
            })?;
        Ok((
            answer.unwrap_or_else(|| Err("the check did not run".to_owned())),
            Some(redeemed.generation),
        ))
    }

    /// One provider call with `value` and its reading, every text in the
    /// answer or the failure cleared by `scrub` with that value.
    fn cleared_check(
        &self,
        check: &str,
        method: &reqwest::Method,
        url: &str,
        value: &[u8],
        scrub: &dyn Fn(&mut String, &[u8]),
    ) -> Checked {
        let mut checked = self
            .send(check, method, url, value)
            .map_err(|error| error.to_string())
            .and_then(|reply| evidence_of(check, reply));
        match &mut checked {
            Ok(evidence) => {
                scrub(&mut evidence.account, value);
                if let Some(provider_account) = evidence.provider_account.as_mut() {
                    scrub(provider_account, value);
                }
                for scope in &mut evidence.scopes {
                    scrub(scope, value);
                }
            }
            Err(failure) => scrub(failure, value),
        }
        checked
    }
}
