//! A credential's verb list (AGENT-CREDENTIAL-VERB-ALLOWLIST; lead 24 Nov
//! 21:4x): "this credential may call only these verbs". The owner names at
//! mint the verbs an agent's credential may call beyond every read verb
//! ([`SlipClaims::verb_allowlist`], signed into the slip), and widens it
//! later by naming a verb in a Grant for its holder: the standing rule
//! of [`principal_standing_or_lapse_in_txn`], which the `verb_grant_caller`
//! doors read too. A credential minted with no list calls every verb its
//! Scope admits, as before.
//!
//! Every server transport that runs a verb for a presented credential asks
//! [`Vault::credential_admits_verb`] first, by the verb's verb-table name.
//! It only narrows: the verb's own scope, Grant, ceiling and write gates
//! still judge the call after it.

use std::collections::BTreeSet;

use super::{SlipClaims, principal_standing_or_lapse_in_txn};
use crate::Vault;
use crate::check_in::{VerbActClass, verb_act_class};
use crate::consent::{
    AGENT_CREDENTIAL_VERBS_WIDEN_COMMAND, AgentCredentialVerbsRow, AgentCredentialVerbsWidenAction,
    CredentialVerbs,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

/// What every refusal of a verb a credential's list leaves out says first.
pub const CREDENTIAL_VERB_NOT_LISTED: &str = "is not among this credential's verbs";

/// Whether `verb` is a read verb: its verb row states the act class `read`
/// (ARCH-0082 #act-table). A Read row with another act class (a model call,
/// an export, code execution) is not one, and neither is a name the verb
/// table does not hold.
#[must_use]
pub fn is_read_verb(verb: &str) -> bool {
    verb_act_class(verb) == Some(VerbActClass::Read)
}

/// Whether a verb list admits `verb` by itself, with no Grant read: a read
/// verb, or one the list names.
#[must_use]
pub fn verb_list_admits(list: &BTreeSet<String>, verb: &str) -> bool {
    is_read_verb(verb) || list.contains(verb)
}

/// The names in `verbs` the verb table does not hold, in order: a verb list
/// names verb-table rows only.
#[must_use]
pub fn unknown_verb_names<'a>(verbs: impl IntoIterator<Item = &'a String>) -> Vec<&'a str> {
    verbs
        .into_iter()
        .map(String::as_str)
        .filter(|verb| verb_act_class(verb).is_none())
        .collect()
}

impl Vault {
    /// Admits a call of `verb` under a credential whose signed claims are
    /// `claims`, any Grant it needs read in a snapshot of its own
    /// ([`Self::credential_admits_verb_in_txn`]).
    ///
    /// # Errors
    ///
    /// `forbidden` for a verb the credential's list leaves out and no Grant
    /// of its holder names; a store read failure.
    pub fn credential_admits_verb(&self, claims: &SlipClaims, verb: &str) -> MemoryResult<()> {
        match &claims.verb_allowlist {
            None => Ok(()),
            Some(list) if verb_list_admits(list, verb) => Ok(()),
            Some(_) => {
                let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
                self.credential_admits_verb_in_txn(&txn, claims, verb)
            }
        }
    }

    /// Admits a call of `verb` in `txn` under a credential whose signed
    /// claims are `claims`: one with no verb list calls every verb; one with
    /// a list calls every read verb, each verb the list names, and each verb
    /// a live Grant from a live owner names its agent holder for (the
    /// owner's widening, judged at each call and gone with the Grant).
    ///
    /// # Errors
    ///
    /// `forbidden` for a verb the credential's list leaves out and no Grant
    /// of its holder names; a store read failure.
    pub fn credential_admits_verb_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        verb: &str,
    ) -> MemoryResult<()> {
        let Some(list) = &claims.verb_allowlist else {
            return Ok(());
        };
        if verb_list_admits(list, verb) || self.holder_grant_names_verb_in_txn(txn, claims, verb)? {
            return Ok(());
        }
        Err(not_listed(verb))
    }

    /// Whether a live Grant from a live owner names the credential's agent
    /// holder and lists `verb` (or a verb class that admits it). A person's
    /// credential has no Grant to widen it.
    fn holder_grant_names_verb_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        verb: &str,
    ) -> MemoryResult<bool> {
        let class = match claims.actor_class.as_deref() {
            Some("agent") => EdgeActorClass::Agent,
            Some("system") => EdgeActorClass::System,
            _ => return Ok(false),
        };
        let Ok(holder) = EntityId::from_hex(&claims.holder_ref) else {
            return Ok(false);
        };
        Ok(matches!(
            principal_standing_or_lapse_in_txn(self, txn, holder, class, verb)?,
            Ok(standing) if standing.grant.is_some()
        ))
    }
}

impl crate::memory::Memory<'_> {
    /// [`Vault::credential_admits_verb`] for the credential this handle's
    /// caller presented: a handle bound to none (the embedded owner's, an
    /// in-process agent run's under its own Grant gates) runs every verb.
    ///
    /// # Errors
    ///
    /// As [`Vault::credential_admits_verb`].
    pub(crate) fn presented_credential_admits_verb(&self, verb: &str) -> MemoryResult<()> {
        match self.presented_credential() {
            Some(proof) => self.vault().credential_admits_verb(proof.claims(), verb),
            None => Ok(()),
        }
    }
}

impl Vault {
    /// The owner's sheet of agent credentials in `txn`: each live slip of a
    /// named agent and the verbs it may call (`all` with no list), newest
    /// issued first, with the owner's widening. Its widening Grants are the
    /// registry's to fill.
    ///
    /// # Errors
    ///
    /// A store, fold or clock failure.
    pub(crate) fn agent_credential_verbs_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> crate::error::Result<Vec<AgentCredentialVerbsRow>> {
        let mut rows: Vec<AgentCredentialVerbsRow> = self
            .live_agent_slips_in_txn(txn)?
            .into_iter()
            .map(|slip| AgentCredentialVerbsRow {
                holder: slip.holder,
                slip_ref: bytes_to_hex_lower(&slip.slip_id),
                issued_at: slip.issued_at,
                expires_at: slip.expires_at,
                verbs: slip
                    .verb_allowlist
                    .map_or(CredentialVerbs::All, CredentialVerbs::Listed),
                widening_grants: Vec::new(),
                widen_action: AgentCredentialVerbsWidenAction {
                    command: AGENT_CREDENTIAL_VERBS_WIDEN_COMMAND.to_owned(),
                    agent: slip.holder,
                },
            })
            .collect();
        rows.sort_by(|left, right| {
            right
                .issued_at
                .cmp(&left.issued_at)
                .then_with(|| left.slip_ref.cmp(&right.slip_ref))
        });
        Ok(rows)
    }
}

/// The refusal of `verb` for a credential whose list leaves it out.
fn not_listed(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "`{verb}` {CREDENTIAL_VERB_NOT_LISTED}: it may call every read verb, the verbs the \
             owner named at its mint and the verbs the owner names in a Grant for its holder"
        ),
        &[
            "Ask the vault owner to name the verb in a Grant for this agent (vault.agents.grants.mint).",
            "Or ask the owner to mint the credential again with the verb (oneiron token agent --verbs).",
        ],
    )
}
