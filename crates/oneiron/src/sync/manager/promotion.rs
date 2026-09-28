//! Opened-window promotion notices on the manager-owned connection lane.

use super::WindowManager;
use crate::sync::WindowKey;

impl WindowManager {
    pub(in crate::sync) fn subscribe_promotions(
        &self,
    ) -> tokio::sync::broadcast::Receiver<WindowKey> {
        self.promotions.subscribe()
    }

    pub(in crate::sync) fn notify_promotion(&self, key: &WindowKey) {
        let _ = self.promotions.send(key.clone());
    }
}
