//! The `[policy]` section: the host's wording and settings for the owner
//! plane's policy notices (FIX 5042), handed to the server's owner policy
//! config at serve start (`SyncServer::with_owner_policy_config`). Every key
//! is optional, and an absent one keeps the engine's default, so a config
//! with no `[policy]` runs as before. The hosted relay's policy is never read
//! from here, and no key decides a verdict: the notices' words, their links
//! and the owner plane's classifier dial.

use oneiron::policy_model::{PolicyModelConfig, RelayClassifierMode};
use oneiron::store::GateSystemNoticeAction;
use serde::Deserialize;

/// Resolved `[policy]` settings, and one layer's keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Shown identically to the person and the model on a human hold.
    pub owner_hold_notice: Option<String>,
    /// The overt retry explanation an owner row's `reword` gives.
    pub owner_reword_notice: Option<String>,
    /// Shown when a `RouteToHelp` sends the person's trusted contact their
    /// check-in notice.
    pub trusted_contact_notified_notice: Option<String>,
    /// Shown when a `RouteToHelp` asks the person before reaching their
    /// trusted contact.
    pub trusted_contact_ask_notice: Option<String>,
    /// Help text a notice carries.
    pub help_message: Option<String>,
    /// Help links a notice carries, each `{label, target}`.
    pub help_resources: Option<Vec<GateSystemNoticeAction>>,
    /// The link an owner-plane notice offers to the setting that fired,
    /// `{label, target}`.
    pub owner_setting_change_offer: Option<GateSystemNoticeAction>,
    /// How much of the owner plane's content reaches the model:
    /// `classify_all` (the engine's default) or `pattern_gated`.
    pub owner_classifier_mode: Option<RelayClassifierMode>,
}

impl PolicyConfig {
    /// A later layer's keys over this one's, key by key.
    pub(super) fn apply_override(&mut self, over: Self) {
        let Self {
            owner_hold_notice,
            owner_reword_notice,
            trusted_contact_notified_notice,
            trusted_contact_ask_notice,
            help_message,
            help_resources,
            owner_setting_change_offer,
            owner_classifier_mode,
        } = over;
        if owner_hold_notice.is_some() {
            self.owner_hold_notice = owner_hold_notice;
        }
        if owner_reword_notice.is_some() {
            self.owner_reword_notice = owner_reword_notice;
        }
        if trusted_contact_notified_notice.is_some() {
            self.trusted_contact_notified_notice = trusted_contact_notified_notice;
        }
        if trusted_contact_ask_notice.is_some() {
            self.trusted_contact_ask_notice = trusted_contact_ask_notice;
        }
        if help_message.is_some() {
            self.help_message = help_message;
        }
        if help_resources.is_some() {
            self.help_resources = help_resources;
        }
        if owner_setting_change_offer.is_some() {
            self.owner_setting_change_offer = owner_setting_change_offer;
        }
        if owner_classifier_mode.is_some() {
            self.owner_classifier_mode = owner_classifier_mode;
        }
    }

    /// The owner plane's policy config these settings make: the engine's
    /// default, with each key set here in its place.
    #[must_use]
    pub fn owner_policy_config(&self) -> PolicyModelConfig {
        let mut config = PolicyModelConfig::default();
        if let Some(text) = &self.owner_hold_notice {
            config.owner_hold_notice = Some(text.clone());
        }
        if let Some(text) = &self.owner_reword_notice {
            config.owner_reword_notice = Some(text.clone());
        }
        if let Some(text) = &self.trusted_contact_notified_notice {
            config.trusted_contact_notified_notice = Some(text.clone());
        }
        if let Some(text) = &self.trusted_contact_ask_notice {
            config.trusted_contact_ask_notice = Some(text.clone());
        }
        if let Some(text) = &self.help_message {
            config.help_message = Some(text.clone());
        }
        if let Some(links) = &self.help_resources {
            config.help_resources.clone_from(links);
        }
        if let Some(offer) = &self.owner_setting_change_offer {
            config.owner_setting_change_offer = Some(offer.clone());
        }
        if let Some(mode) = self.owner_classifier_mode {
            config.owner_classifier_mode = mode;
        }
        config
    }
}
