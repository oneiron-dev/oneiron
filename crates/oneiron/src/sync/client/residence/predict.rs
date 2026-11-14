//! A predicted machine's ask for a prediction and its fetch of the predicted set the home names.
//! The entry point is `SyncClient::ask_prediction`.
//! Vocabulary owned by `super`.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::super::base::SyncClient;
use super::super::types::SyncResidenceMode;
use crate::EntityId;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

use super::rpc::{ResidenceRpc, refused, residence_budgets};

/// What the home answered to one `residence.predict` ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PredictionAsk {
    /// The home pushed a prediction: the pushed directive's id. The machine takes it through the
    /// authority catch-up, as any directive.
    Pushed(EntityId),
    /// The machine's prediction stands: nothing new to take.
    Unchanged,
}

impl PredictionAsk {
    /// The pushed prediction's directive, when the home pushed one.
    pub(crate) fn pushed(self) -> Option<EntityId> {
        match self {
            Self::Pushed(directive) => Some(directive),
            Self::Unchanged => None,
        }
    }
}

/// The home's answer to `residence.predict`: `pushed` with the directive, or `unchanged`.
#[derive(Deserialize)]
struct PredictionAskReply {
    state: String,
    directive: Option<String>,
}

/// One page of the predicted set body `residence.predicted_set` serves.
#[derive(Deserialize)]
struct PredictedSetPartReply {
    digest: String,
    offset: u64,
    total: u64,
    part: String,
}

impl SyncClient {
    /// Asks the home once whether it pushed a prediction for this machine (Engine ruling
    /// L7-46-MERGE A). An opened mode and a residence selector are required, as for the other
    /// residence calls; a home no socket reaches is [`TransportError::home_offline`].
    pub(crate) async fn ask_prediction(&mut self) -> Result<PredictionAsk, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let budgets = residence_budgets(&self.vault)?;
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::home_offline());
        };
        let reply: PredictionAskReply = serde_json::from_value(
            rpc.request("residence.predict", json!({ "selector": selector }))
                .await?,
        )
        .map_err(|_| refused())?;
        match reply.state.as_str() {
            "pushed" => {
                let Some(hex) = reply.directive.as_deref() else {
                    return Err(refused());
                };
                let directive = EntityId::from_hex(hex).map_err(|_| refused())?;
                if directive.to_hex().as_str() != hex {
                    return Err(refused());
                }
                Ok(PredictionAsk::Pushed(directive))
            }
            "unchanged" => Ok(PredictionAsk::Unchanged),
            _ => Err(refused()),
        }
    }

    /// Fetches the predicted set body `digest` names from the home, part by part from offset 0
    /// until the bytes read are the total (BUDGET-CEILING). A reply whose offset or digest
    /// differs from the request, an empty part before the end, or a total that changes between
    /// parts is refused.
    pub(crate) async fn fetch_predicted_set(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let budgets = residence_budgets(&self.vault)?;
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::home_offline());
        };
        let hex = crate::entity_id::bytes_to_hex_lower(digest);
        let mut body = Vec::new();
        let mut total: Option<u64> = None;
        loop {
            let offset = u64::try_from(body.len()).map_err(|_| refused())?;
            let reply: PredictedSetPartReply = serde_json::from_value(
                rpc.request(
                    "residence.predicted_set",
                    json!({ "digest": hex, "offset": offset }),
                )
                .await?,
            )
            .map_err(|_| refused())?;
            if reply.digest != hex || reply.offset != offset {
                return Err(refused());
            }
            if total.is_some_and(|known| known != reply.total) {
                return Err(refused());
            }
            total = Some(reply.total);
            let part = base64::engine::general_purpose::STANDARD
                .decode(&reply.part)
                .map_err(|_| refused())?;
            let end = offset
                .checked_add(u64::try_from(part.len()).map_err(|_| refused())?)
                .ok_or_else(refused)?;
            if end > reply.total {
                return Err(refused());
            }
            if part.is_empty() && end != reply.total {
                return Err(refused());
            }
            body.extend_from_slice(&part);
            if end == reply.total {
                return Ok(body);
            }
        }
    }

    /// The cached thin index's first item of `window` (`ri:w:{window}:{item}`), the anchor a
    /// prefetch admits the window's promotion through. `None` when the index holds no item of
    /// the window: it is skipped this pass.
    pub(crate) fn thin_index_anchor(
        &self,
        window: &WindowKey,
    ) -> Result<Option<EntityId>, TransportError> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let prefix = format!("ri:w:{window}:");
        for row in self
            .vault
            .store
            .sync_state
            .prefix_iter(&txn, &prefix)
            .map_err(|error| TransportError::Storage(error.to_string()))?
        {
            let (key, _) = row.map_err(|error| TransportError::Storage(error.to_string()))?;
            if let Some(tag) = key.strip_prefix(prefix.as_str())
                && let Ok(id) = EntityId::from_hex(tag)
                && id.to_hex().as_str() == tag
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}
