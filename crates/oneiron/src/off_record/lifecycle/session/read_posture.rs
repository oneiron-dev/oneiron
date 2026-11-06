//! Owning-vault posture for composed session content reads.

impl super::OffRecordSession<'_> {
    pub(crate) fn privacy_posture(&self) -> crate::HostingPrivacyPosture {
        self.vault.privacy_posture()
    }
}
