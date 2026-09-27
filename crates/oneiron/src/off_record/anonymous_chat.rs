//! Stateless, memory-free chat beside (not inside) agent chat and off-record promote.
//!
//! The only vault read is the owner-policy manifest. The responder receives a
//! target and one turn's text, never a vault, session view, memory pack, or
//! earlier turns. The anonymous session substrate supplies an in-process
//! lifetime and a discard-only write route; this API exposes no memory reads.

use std::future::Future;
use std::pin::Pin;

use crate::Vault;
use crate::error::{Error, Result};
use crate::llm::{BudgetLease, LlmBackend};
use crate::policy_model::{PolicyClassifyDecision, PolicyModelConfig};
use crate::store::GateSystemNoticeRecord;

use super::{OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode, OffRecordSession};

/// The host chooses the house-mind configuration or a plain model. Neither
/// selection imports memory; prompts and model identities stay host-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousChatTarget {
    HouseMind,
    PlainModel,
}

/// A single, context-free model invocation. Implementations must not add
/// previous turns or vault memory; the engine passes neither to this seam.
pub trait AnonymousChatResponder: Send + Sync {
    fn respond<'a>(
        &'a self,
        target: AnonymousChatTarget,
        text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;
}

/// A shared system notice has `audience = user_and_model`. The host must
/// display the SAME notice to the person and pass it to the model's notice
/// channel, without inserting either copy into the chat or vault transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnonymousChatTurn {
    Reply {
        content: String,
        /// Warnings on input or output, in evaluation order.
        notices: Vec<GateSystemNoticeRecord>,
    },
    Blocked {
        /// `true` when the incoming turn was withheld before the model ran.
        input: bool,
        notice: Box<GateSystemNoticeRecord>,
    },
}

/// No getter exposes the underlying off-record session or vault. It is NOT
/// `OffRecordSession`: that session permits composed reads of base memory.
pub struct AnonymousChatSession<'vault> {
    session: OffRecordSession<'vault>,
}

impl Vault {
    /// Open a traceless chat. Close explicitly when done. This does not
    /// record a session row in the vault and cannot flip into on-record mode.
    pub fn open_anonymous_chat(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<AnonymousChatSession<'_>> {
        Ok(AnonymousChatSession {
            session: self
                .off_record_session_vault()
                .enter_anonymous(session_ref, backend)?,
        })
    }
}

impl AnonymousChatSession<'_> {
    /// Classify BOTH the person's turn and the model's reply. A blocking
    /// input is never sent to the responder; a blocking output never escapes.
    /// No classify/enforce receipt door is called, even for policy violations.
    pub async fn chat(
        &self,
        text: &str,
        target: AnonymousChatTarget,
        responder: &dyn AnonymousChatResponder,
        policy_backend: &dyn LlmBackend,
        policy_lease: &BudgetLease,
        policy_config: &PolicyModelConfig,
    ) -> Result<AnonymousChatTurn> {
        let route = self.session.write_route()?;
        debug_assert_eq!(self.session.mode()?, OffRecordMode::Anonymous);
        let vault = self.session.vault;
        let (decision, mut notices) = crate::policy_model::stateless_owner_classification(
            vault,
            text,
            policy_config,
            policy_backend,
            policy_lease,
        )
        .await?;
        route.revalidate()?;
        if halts(decision) {
            let notice = notices.into_iter().next().ok_or(Error::InvariantViolation(
                "anonymous chat block must have a policy notice",
            ))?;
            return Ok(AnonymousChatTurn::Blocked {
                input: true,
                notice: Box::new(notice),
            });
        }

        let content = responder.respond(target, text).await?;
        route.revalidate()?;
        let (decision, mut output_notices) = crate::policy_model::stateless_owner_classification(
            vault,
            &content,
            policy_config,
            policy_backend,
            policy_lease,
        )
        .await?;
        route.revalidate()?;
        if halts(decision) {
            let notice = output_notices
                .into_iter()
                .next()
                .ok_or(Error::InvariantViolation(
                    "anonymous chat block must have a policy notice",
                ))?;
            return Ok(AnonymousChatTurn::Blocked {
                input: false,
                notice: Box::new(notice),
            });
        }
        notices.append(&mut output_notices);
        Ok(AnonymousChatTurn::Reply { content, notices })
    }

    /// The session closes without a transcript, telemetry, or gate receipt.
    pub fn close(self) -> Result<OffRecordCloseOutcome> {
        self.session.close()
    }
}

const fn halts(decision: PolicyClassifyDecision) -> bool {
    matches!(
        decision,
        PolicyClassifyDecision::Block
            | PolicyClassifyDecision::RouteToHelp
            | PolicyClassifyDecision::Hold
    )
}
