//! Bearer option-link calls. Machine routing locates the issuer; the original
//! Vault entrypoints alone admit the bearer and produce its result.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::memory::MemoryResult;
use crate::task_verb::{ConsultPayloadRef, TaskAskAnswer, TaskAskOptionId, TaskAskOptionLinkView};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AskOptionLinkRequest {
    View {
        token: String,
    },
    Answer {
        token: String,
        option: TaskAskOptionId,
        source_refs: BTreeSet<ConsultPayloadRef>,
    },
    Void {
        token: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", content = "result", rename_all = "snake_case")]
pub enum AskOptionLinkReply {
    View(MemoryResult<TaskAskOptionLinkView>),
    Answer(MemoryResult<TaskAskAnswer>),
    Void(MemoryResult<()>),
}

impl AskOptionLinkRequest {
    /// Runs off an async worker: an answer waits on the original task-work line.
    pub fn execute(self, vault: &Vault) -> AskOptionLinkReply {
        match self {
            Self::View { token } => AskOptionLinkReply::View(vault.ask_option_link_view(&token)),
            Self::Answer {
                token,
                option,
                source_refs,
            } => AskOptionLinkReply::Answer(vault.answer_ask_option_link_with_sources(
                &token,
                &option,
                &source_refs,
            )),
            Self::Void { token } => AskOptionLinkReply::Void(vault.void_ask_option_link(&token)),
        }
    }
}
