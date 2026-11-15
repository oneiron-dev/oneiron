//! The blob-artifact Setting key (restriction wave 13, census C112; the owner's principle of 16
//! Nov: an optional freedom with a good default): how many ops one image edit takes. The organ
//! host reads it before it calls the image organ (`oneiron_organ_host::image::edit_image`). The
//! default is the count the host has always taken. The owner changes it; an agent's change waits
//! on the owner's approval.
//!
//! Direction: a lower count is tighter, since an edit with more ops is refused before the organ
//! runs. A row that does not decode reads as one op. The host sends the count with its
//! `image.render` call, and the organ applies it in place of its own default of 256. Whatever the
//! count, the organ's own memory grant and frame limits still bound each call (`too_large`).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The ops one image edit has always taken.
const DEFAULT_IMAGE_EDIT_MAX_OPS: u32 = 256;

/// How many ops one image edit takes: at least 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ImageEditOpLimit(pub(crate) u32);

impl SettingValue for ImageEditOpLimit {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "an image edit takes at least 1 op".to_owned(),
            ))
        }
    }
}

fn default_image_edit_max_ops() -> ImageEditOpLimit {
    ImageEditOpLimit(DEFAULT_IMAGE_EDIT_MAX_OPS)
}

fn fewest_image_edit_ops() -> ImageEditOpLimit {
    ImageEditOpLimit(1)
}

crate::setting::setting_keys! {
    /// The most ops one image edit takes (default 256). Lower is tighter: the organ host refuses
    /// an edit with more ops (`too_many_ops`) before it reads the source or calls the organ.
    pub(crate) ORGAN_HOST_IMAGE_MAX_OPS: ImageEditOpLimit = "organ_host.image.max_ops" {
        kind: Kind::new(default_image_edit_max_ops)
            .strictest(fewest_image_edit_ops)
            .tighter(lower_is_tighter::<ImageEditOpLimit>),
    };
}

/// The most ops one image edit takes, as the vault's settings give it now, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub fn image_edit_max_ops(vault: &Vault) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let limit = ORGAN_HOST_IMAGE_MAX_OPS
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0;
    Ok(usize::try_from(limit).unwrap_or(usize::MAX))
}
