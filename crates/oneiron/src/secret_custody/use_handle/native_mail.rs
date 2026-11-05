//! The host's native mail readiness check as a `self.use` table operation.
//! Placement comes from the host; the credential is only the admitted use's
//! record, presented and cleared inside its own T0 door.

use serde_json::{Value, json};

use super::{SecretUseTarget, SentPresentation, SentValue, handle_text};
use crate::channel_identity_provider::stalwart::{StalwartClient, StalwartConfig};
use crate::vault::Vault;

pub(super) fn check(
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> std::result::Result<Value, String> {
    if arguments
        .as_object()
        .is_some_and(|fields| !fields.is_empty())
    {
        return Err(format!("{} takes no arguments", target.operation));
    }
    let placement = vault
        .served_transports()
        .native_mail()
        .cloned()
        .ok_or_else(|| "this host names no native mail server".to_owned())?;
    let text = handle_text(target.handle);
    let mut answer = None;
    let mut present = |value: &[u8]| -> crate::error::Result<()> {
        let mut checked = connect(&placement, value);
        let sent = SentValue::new(value, &text);
        match &mut checked {
            Ok(result) => sent.clear_json(result),
            Err(failure) => sent.clear_string(failure),
        }
        answer = Some(checked);
        // A provider failure still presented this generation. Keep it as
        // the answer, not a door error that loses the presentation receipt.
        Ok(())
    };
    let door = match target.grant {
        Some((grant, granted)) => vault
            .redeem_secret_grant_at_door(&grant, granted, &mut present)
            .map(|receipt| receipt.generation),
        None => {
            let presented = match target.run() {
                Some(run) => {
                    vault.with_run_secret_for(run, target.handle, target.effector, &mut present)
                }
                None => vault.present_resolved_secret_at_door(
                    &target.custody,
                    target.effector,
                    &mut present,
                ),
            };
            presented.map(|receipt| receipt.value_generation)
        }
    };
    match door {
        Ok(generation) => {
            target.note_sent(Some(SentPresentation::cleared(target.custody, generation)));
            answer.unwrap_or_else(|| Err("the mail server check did not run".to_owned()))
        }
        Err(refusal) => {
            let failure = refusal.to_string();
            target.refuse(refusal);
            Err(failure)
        }
    }
}

fn connect(placement: &StalwartConfig, value: &[u8]) -> std::result::Result<Value, String> {
    let authorization = authorization_header(value)?;
    StalwartClient::connect(placement.clone(), authorization)
        .map_err(|error| format!("the mail server refused the check: {error}"))?;
    Ok(json!({
        "account": format!("{} on {}", placement.domain(), placement.instance_ref()),
        "provider_account": placement.domain(),
        "scopes": [],
    }))
}

/// The same whole-header or bare-token format the native mail pack accepts.
fn authorization_header(value: &[u8]) -> std::result::Result<reqwest::header::HeaderValue, String> {
    let value = std::str::from_utf8(value)
        .map_err(|_| "the stored credential is not text".to_owned())?
        .trim();
    let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
        value.to_owned()
    } else {
        format!("Bearer {value}")
    };
    reqwest::header::HeaderValue::from_str(&header)
        .map_err(|_| "the stored credential is not a header value".to_owned())
}
