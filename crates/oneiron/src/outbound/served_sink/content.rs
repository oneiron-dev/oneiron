//! The text an outbound content ref sends (OF-187): one resolver over the
//! typed content-family loaders this engine has. A ref no loader claims
//! resolves to nothing; a bare entity id is never dumped as text.

use crate::campaign::step_body::CAMPAIGN_STEP_BODY_PREFIX;
use crate::dreamer_runner::maintenance::representation::REPRESENTATION_CONTENT_PREFIX;
use crate::error::{Error, Result};
use crate::outbound::reply_content::CONNECTOR_REPLY_BODY_PREFIX;
use crate::task_verb::TaskAskSoftConfirmNotice;
use crate::{EntityId, Vault};

/// The check-in line a trusted contact's notice (OF-527) reads, the same
/// every time: the fact of concern, never a word of the conversation.
const TRUSTED_CONTACT_CHECK_IN_TEXT: &str = "Having a hard night, please check in.";

impl Vault {
    /// The plain text an outbound content ref sends, when this engine has a
    /// typed loader for it: an agent's connector reply body, a campaign
    /// program step's filed body, approved representation content, a
    /// commitment reminder, a soft-confirm notice (scheduled by its bare
    /// notice id, FIX 1469), or a trusted contact's fixed check-in line.
    pub fn outbound_content_text(&self, content_ref: &str) -> Result<Option<String>> {
        if content_ref == crate::counterparty_contact::TRUSTED_CONTACT_NOTICE_CONTENT_REF {
            return Ok(Some(TRUSTED_CONTACT_CHECK_IN_TEXT.to_owned()));
        }
        if content_ref.starts_with(CONNECTOR_REPLY_BODY_PREFIX) {
            return self.connector_reply_body_text(content_ref);
        }
        if content_ref.starts_with(CAMPAIGN_STEP_BODY_PREFIX) {
            return self.campaign_step_body_text(content_ref);
        }
        // The approved content as approved, its approval and sources
        // revalidated by the representation loader itself.
        if content_ref.starts_with(REPRESENTATION_CONTENT_PREFIX) {
            let bytes = self.read_representation_content(content_ref)?;
            return String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| Error::InvalidClaimBody("representation content is not text"));
        }
        if let Some(text) = self.commitment_reminder_text(content_ref)? {
            return Ok(Some(text));
        }
        let Ok(id) = EntityId::from_hex(content_ref) else {
            return Ok(None);
        };
        Ok(self
            .ask_soft_confirm_notice_by_content_ref(id)?
            .as_ref()
            .map(soft_confirm_notice_text))
    }
}

/// The one rendering of a soft-confirm notice (FIX 1469): its facts in a
/// fixed structured form, the task and the companion answer it asks about,
/// the revision and the deadline (Unix seconds). Wording and language are
/// the consumer's; this default invents no prose and no consent language.
fn soft_confirm_notice_text(notice: &TaskAskSoftConfirmNotice) -> String {
    format!(
        "task_ref: {}\ncompanion_answer_ref: {}\nrevision: {}\ndeadline: {}",
        notice.task_ref.to_hex(),
        notice.companion_answer_ref.to_hex(),
        notice.revision,
        notice.deadline,
    )
}
