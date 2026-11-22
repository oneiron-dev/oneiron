//! Connector elicitation answer binding and verdict, and the check that
//! authorizes an answer under the original call's grant.

use super::*;

/// What one live connector question binds (ONE-2510): the original call's
/// principal, its exact standing grant, the governing key the call was
/// prepared against, the catalog name it called, and the server, tool and
/// endpoint the grant admitted. An answer is checked under exactly these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorElicitationBinding {
    /// The calling actor, hex.
    pub principal_ref: String,
    pub grant_id: EntityId,
    /// The governing connector key (`FrozenToolCallView::key_ref`).
    pub key_ref: EntityId,
    /// The catalog name the call named.
    pub name: String,
    pub server: String,
    pub tool: String,
    pub endpoint: String,
}

/// How one answer to a connector's question may go out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElicitationAnswerVerdict {
    /// Send the answer as given.
    Send,
    /// Ask the owner about this exact answer first.
    AskOwner,
    /// The original grant no longer covers the answer: the owner must
    /// change the grant. The question stays live, so a retry can land.
    Escalate(String),
    /// The answer may not go: the question is cancelled instead.
    Refuse(String),
}

impl Vault {
    /// Whether an answer to a live connector question may go out, under the
    /// original call's exact grant and principal (ONE-2510). A decline or a
    /// cancel carries no content and always goes. An accept needs that very
    /// grant (never another the principal holds) still active under the
    /// policy floor, still the principal's, and still admitting the original
    /// server, tool, endpoint and data class, on an active governing key;
    /// otherwise it escalates (a revoked key refuses). Then the key's
    /// elicitation setting, read now, decides: never allow refuses, always
    /// allow sends, always ask asks the owner unless a standing grant the
    /// owner's stop-asking press minted covers the answer (FIX 8808), and
    /// auto takes rule 1 under the original grant. `answers` is the frozen
    /// answer, whose own content class counts beside the tool's (FIX 8807);
    /// `answer` names its round and digest, for the record and the owner's
    /// consent, never its text. Each grant, key and slate the check reads
    /// lists on `memory`'s answer (FIX 5816).
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn authorize_connector_elicitation_answer(
        &self,
        memory: &crate::memory::Memory<'_>,
        binding: &ConnectorElicitationBinding,
        answers: &serde_json::Value,
        answer: &ConnectorElicitationAnswer<'_>,
        carries_content: bool,
    ) -> crate::Result<ElicitationAnswerVerdict> {
        let verdict = if carries_content {
            let mut read = Vec::new();
            let verdict = self.elicitation_answer_verdict(binding, answers, answer, &mut read);
            memory.produced_from(read);
            verdict?
        } else {
            ElicitationAnswerVerdict::Send
        };
        tracing::debug!(
            grant = %binding.grant_id.to_hex(),
            key = %binding.key_ref.to_hex(),
            answers = %crate::entity_id::bytes_to_hex_lower(&answer.digest),
            ?verdict,
            "connector elicitation answer authorized"
        );
        Ok(verdict)
    }

    /// The verdict on an answer that carries content: the grant's half
    /// ([`Self::elicitation_answer_grant_verdict_in_txn`]) in one snapshot,
    /// then the key's elicitation setting.
    fn elicitation_answer_verdict(
        &self,
        binding: &ConnectorElicitationBinding,
        answers: &serde_json::Value,
        answer: &ConnectorElicitationAnswer<'_>,
        read: &mut Vec<EntityId>,
    ) -> crate::Result<ElicitationAnswerVerdict> {
        let held = {
            let txn = self.store.env.read_txn()?;
            self.elicitation_answer_grant_verdict_in_txn(&txn, binding, answers, read)?
        };
        if let Some(verdict) = held {
            return Ok(verdict);
        }
        Ok(
            match self.connector_elicitation_setting(&binding.key_ref)? {
                crate::connector_key::SlateDisposition::NeverAllow => {
                    ElicitationAnswerVerdict::Refuse("elicitation_never_allow".to_owned())
                }
                crate::connector_key::SlateDisposition::AlwaysAsk => {
                    self.always_ask_elicitation_verdict(binding, answer)
                }
                // Rule 1 under the original grant: a reversible answer runs, and
                // an irreversible one runs because the standing grant checked
                // above covers it. Always allow folds in as that covering grant.
                crate::connector_key::SlateDisposition::Auto
                | crate::connector_key::SlateDisposition::AlwaysAllow => {
                    ElicitationAnswerVerdict::Send
                }
            },
        )
    }
}
