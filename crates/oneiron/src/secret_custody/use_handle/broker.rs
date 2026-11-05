//! The host's brokered model listing, using only this use's credential.

use std::fmt::Debug;

use serde::Deserialize;
use serde_json::Value;

use super::{SecretUseTarget, SentPresentation, SentValue, handle_text};
use crate::vault::Vault;

/// A read-only model listing through the host's credential broker.
pub const SECRET_USE_BROKER_MODELS: &str = "broker.models";

/// The host's configured model providers, without custody or actor authority.
/// The engine calls this on the operation's own blocking thread.
pub trait BrokerModelListingHost: Debug + Send + Sync {
    /// Checks the configured provider's immutable request and connects to the
    /// broker before the engine releases any credential. `call` is the use's
    /// already-committed intent id. No credential is read here.
    fn prepare(
        &self,
        provider: &str,
        call: &str,
    ) -> Result<Box<dyn BrokerModelListingCall>, String>;
}

/// One checked request on an already-connected broker, never another target.
pub trait BrokerModelListingCall: Send {
    /// Sends once with the exact bytes this use's door released. The result
    /// stays inside that door until the engine clears it of those bytes.
    fn present(self: Box<Self>, value: &[u8]) -> BrokerModelListingReply;
}

/// The operation's native result and whether the broker accepted its send.
/// A connection alone is not a presentation. An unanswered/lost channel does
/// not establish one either.
pub struct BrokerModelListingReply {
    pub result: Result<Value, String>,
    pub presented: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    provider: String,
}

pub(super) fn models(
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> Result<Value, String> {
    let Arguments { provider } = serde_json::from_value(arguments.clone())
        .map_err(|_| "broker.models takes {provider: a configured provider name}".to_owned())?;
    let transports = vault.served_transports();
    let host = transports
        .broker_model_listing()
        .ok_or_else(|| "this host installs no broker model listing".to_owned())?;
    let mut prepared = Some(host.prepare(&provider, &target.context().intent.to_hex())?);
    let text = handle_text(target.handle);
    let mut answer = None;
    let mut presented = false;
    let mut present = |value: &[u8]| -> crate::error::Result<()> {
        let Some(prepared) = prepared.take() else {
            answer = Some(Err("the broker request was already sent".to_owned()));
            return Ok(());
        };
        let reply = prepared.present(value);
        let mut checked = reply.result;
        presented = reply.presented;
        let sent = SentValue::new(value, &text);
        match &mut checked {
            Ok(result) => sent.clear_json(result),
            Err(failure) => sent.clear_string(failure),
        }
        answer = Some(checked);
        // A provider failure is an operation result, not a custody refusal.
        Ok(())
    };
    let door = match target.grant {
        Some((grant, granted)) => vault
            .redeem_secret_grant_at_door(&grant, granted, &mut present)
            .map(|receipt| receipt.generation),
        None => {
            let receipt = match target.run() {
                Some(run) => {
                    vault.with_run_secret_for(run, target.handle, target.effector, &mut present)
                }
                None => vault.present_resolved_secret_at_door(
                    &target.custody,
                    target.effector,
                    &mut present,
                ),
            };
            receipt.map(|receipt| receipt.value_generation)
        }
    };
    match door {
        Ok(generation) => {
            if presented {
                target.note_sent(Some(SentPresentation::cleared(target.custody, generation)));
            }
            answer.unwrap_or_else(|| Err("the broker model listing did not run".to_owned()))
        }
        Err(refusal) => {
            let failure = refusal.to_string();
            target.refuse(refusal);
            Err(failure)
        }
    }
}
