//! A device's admission of the masked repo copies its home sends (FIX 7608
//! slice 4, LEAF 4.3).
//!
//! What arrives on a copy is translated onto its source before this device
//! imports it, after the envelope's pads are installed: a copy edit lands on
//! the stored bytes through the shipped visible diff, and a ruled hold
//! imports nothing (the home sends it again). A device holding no marked
//! repo item imports every payload as it came.

use super::base::SyncClient;
use crate::sync::selector::RepoSyncAdmission;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

impl SyncClient {
    /// `payload`, an admitted window envelope's payload for `key`, as this
    /// window imports it; `None` for a ruled hold.
    pub(super) fn admitted_window_payload(
        &self,
        key: &WindowKey,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let window = self.window(key.as_str());
        let admitted = crate::sync::selector::admit_repo_sync_frame(
            &self.vault,
            key.as_str(),
            &payload,
            window.as_ref().map(|window| &window.doc),
        )
        .map_err(|error| TransportError::Storage(error.to_string()))?;
        Ok(match admitted {
            RepoSyncAdmission::Admit(std::borrow::Cow::Borrowed(_)) => Some(payload),
            RepoSyncAdmission::Admit(std::borrow::Cow::Owned(translated)) => Some(translated),
            RepoSyncAdmission::Held => None,
        })
    }

    /// `payload`, a whole window state the home sent for `key` (bulk state
    /// or a promotion snapshot), as this window takes it: its copy rows
    /// translated onto the sources this device holds. A state nothing here
    /// can take as a source edit (a ruled hold) is taken as it came: its
    /// copy rows stay copy rows under their own ids, masked, and no source
    /// row changes.
    pub(super) fn admitted_whole_payload(
        &self,
        key: &WindowKey,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, TransportError> {
        let admitted =
            crate::sync::selector::admit_repo_sync_frame(&self.vault, key.as_str(), &payload, None)
                .map_err(|error| TransportError::Storage(error.to_string()))?;
        Ok(match admitted {
            RepoSyncAdmission::Admit(std::borrow::Cow::Owned(translated)) => translated,
            RepoSyncAdmission::Admit(std::borrow::Cow::Borrowed(_)) => payload,
            RepoSyncAdmission::Held => {
                tracing::warn!(
                    window = key.as_str(),
                    "sync: a whole window state holds a copy edit on its ruled cause; its copy rows stay copies"
                );
                payload
            }
        })
    }
}
