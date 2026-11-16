//! The setting keys `batch` declares (Setting stage 1): the crate's build script lists each row
//! in the setting catalogue.

use super::secret_scan::SecretScanMode;
use crate::check_in::ActClass;
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The vault's `secrets` switch: whether the write door scans what a host writes into this
    /// vault for credential shapes. On unless the owner switches it off; serve and export redact
    /// credentials in both modes. A row that does not decode reads on, so the scan fails closed.
    /// Switching it is a security control's act (ARCH-0082 act table), and switching it back on
    /// queues a historical lift run for what was stored while it was off.
    pub(crate) SECRET_SCAN_MODE: SecretScanMode = "secret_scan.mode" {
        kind: Kind::new(SecretScanMode::default).strictest(SecretScanMode::default),
        act: ActClass::SecurityControlDisable,
        on_change: Some(crate::policy_model::secret_scan_switched_in_txn),
    };
}
