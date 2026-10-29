//! The provider key for one web call. The deploy's backend key comes from its
//! environment; the owner's own key is copied out at the custody door and
//! wiped on drop, so the send never runs inside the door's write transaction.
//! A key value is never logged, printed or stored.
use oneiron::web_connector::{
    BACKEND_KEY_ENV, WEB_CONNECTOR_EFFECTOR, WebConnectorSetting, WebKeySource, WebProviderKey,
};
use zeroize::Zeroizing;

use crate::server::SyncServer;

/// A provider key for one call, wiped when dropped.
pub(super) struct ProviderKey {
    value: Zeroizing<String>,
}

impl ProviderKey {
    pub(super) fn expose(&self) -> &str {
        &self.value
    }
}

/// The key the switch names for its provider, or the reason code a refusal
/// answers with. A hub key has none here: the hub connector's own call
/// presents it.
pub(super) fn provider_key(
    server: &SyncServer,
    setting: &WebConnectorSetting,
) -> Result<ProviderKey, &'static str> {
    match &setting.key {
        WebProviderKey::Backend => {
            if !setting.provider.profile().backend_key {
                return Err("web_provider_backend_key_not_allowed");
            }
            let value = Zeroizing::new(std::env::var(BACKEND_KEY_ENV).unwrap_or_default());
            if value.trim().is_empty() {
                return Err("web_provider_key_missing");
            }
            Ok(ProviderKey {
                value: Zeroizing::new(value.trim().to_owned()),
            })
        }
        WebProviderKey::Secret { name } => {
            let mut bytes = Zeroizing::new(Vec::new());
            let read = server.vault().inject_secret_at_door(
                name,
                WEB_CONNECTOR_EFFECTOR,
                &mut |value: &[u8]| {
                    // Sized once, so no reallocation leaves an unwiped copy.
                    bytes.reserve_exact(value.len());
                    bytes.extend_from_slice(value);
                    Ok(())
                },
            );
            if let Err(error) = read {
                tracing::warn!(%error, secret = %name, "web connector key not read at the custody door");
                return Err("web_provider_key_unavailable");
            }
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| "web_provider_key_invalid")?
                .trim();
            if value.is_empty() {
                return Err("web_provider_key_missing");
            }
            Ok(ProviderKey {
                value: Zeroizing::new(value.to_owned()),
            })
        }
        WebProviderKey::Hub { .. } => Err("web_provider_key_missing"),
    }
}

/// Whose key a switch's call runs on.
pub(super) fn key_source(setting: &WebConnectorSetting) -> WebKeySource {
    match setting.key {
        WebProviderKey::Backend => WebKeySource::Backend,
        WebProviderKey::Secret { .. } => WebKeySource::User,
        WebProviderKey::Hub { .. } => WebKeySource::Hub,
    }
}
