//! `can({verb})`: one verb's gate for one actor (FIX [UI-GATE-PREVIEW];
//! GENUI-WIRE-GAPS section 4 item 1; ARCH-0082: "`can(effect)` is the same
//! call with no side effects").
//!
//! The answer reads the same admission the verb's own call meets first, in a
//! read transaction: no write, no consent spent, no ask opened, no hook run.
//! A verb whose row asks the owner's credential or a person's proof
//! (`AgentVerb::takes_person_proof`) answers `person` for any actor that is
//! not a person, since the dispatch refuses that call before its door runs.
//! The room pin doors, the pin policy and the room invitation are read
//! through their own admission functions; every other verb answers
//! `unchecked`. A refusal answers with the call's own refusal, so the app
//! shows the words the call would.
//!
//! Who may be judged: the caller, or, for the vault's owner, any of the
//! vault's own agents. The owner reads the vault whole already; an agent or
//! another person naming someone else is refused. A judgment for a named
//! agent reads its standing in the vault, not one credential's narrower
//! scope, which the call itself checks when it runs.

use super::{CanVerbAnswer, CanVerbGate};
use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryResult};
use crate::error::Error;
use crate::verbs::{AgentVerb, CanVerb};
use crate::workspace_roster::{JoinRequest, RoomPinPolicySet, RoomPinRequest};
use crate::{EdgeActorClass, EntityId};

/// The reason `person` carries for a verb whose row asks a person's proof.
const PERSON_PROOF: &str = "this verb's door takes the owner's credential or a person's proof, which no agent's call presents; a person acts instead";

impl Memory<'_> {
    /// `can({verb})`: `request`'s verb gate for its actor, dated.
    pub(super) fn can_verb(&self, request: &CanVerb) -> MemoryResult<CanVerbAnswer> {
        let verb = AgentVerb::from_name(&request.name).ok_or_else(|| {
            MemoryError::bad_request_with(
                "can({verb}) names no verb of the catalog",
                &["Name a verb as the SDK catalog spells it, for example vault.rooms.pins.pin."],
            )
        })?;
        let named;
        let actor: &Memory<'_> = match request.actor {
            Some(actor) if actor != self.actor => {
                self.require_names_own_agent(actor)?;
                named = self.vault.memory(actor, EdgeActorClass::Agent);
                &named
            }
            _ => self,
        };
        let (gate, reasons) = actor.verb_gate(verb, &request.params)?;
        let checked_at = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            crate::ports::job_recorded_at_in_txn(&self.vault.store, &txn)?
        };
        Ok(CanVerbAnswer {
            verb: verb.as_str().to_owned(),
            actor_ref: actor.actor,
            actor_kind: actor.actor_class,
            gate,
            reasons,
            checked_at,
        })
    }

    /// Refuses unless the caller is the vault's owner and `actor` is one of
    /// the vault's own agents.
    fn require_names_own_agent(&self, actor: EntityId) -> MemoryResult<()> {
        if !self.is_vault_owner()? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only the vault's owner asks can({verb}) for another actor",
                &["Omit actor to read your own gate."],
            ));
        }
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let fold = self.vault.authority_fold_readonly_in_txn(&txn)?;
        if !crate::disclosure::is_vault_agent_in(self.vault, &txn, &fold, &actor)? {
            return Err(MemoryError::bad_request_with(
                "actor names none of this vault's agents",
                &["Name one of the vault's own agents, or omit actor."],
            ));
        }
        Ok(())
    }

    /// This actor's gate for one call of `verb` with `params`, and its
    /// reasons.
    fn verb_gate(
        &self,
        verb: AgentVerb,
        params: &serde_json::Value,
    ) -> MemoryResult<(CanVerbGate, Vec<String>)> {
        let person = self.actor_class == EdgeActorClass::Human;
        if !person && verb.takes_person_proof() {
            return Ok((CanVerbGate::Person, vec![PERSON_PROOF.to_owned()]));
        }
        let name = verb.as_str();
        let (admission, persons_act) = match name {
            "vault.rooms.pins.pin" => (
                self.rooms_pins_pin_admission(&verb_input::<RoomPinRequest>(name, params)?),
                false,
            ),
            "vault.rooms.pins.unpin" => (
                self.rooms_pins_unpin_admission(&verb_input::<RoomPinRequest>(name, params)?),
                false,
            ),
            "vault.rooms.pins.policy.set" => (
                self.rooms_pins_policy_set_admission(&verb_input::<RoomPinPolicySet>(
                    name, params,
                )?),
                true,
            ),
            "vault.rooms.invite" => (
                self.rooms_invite_admission(&verb_input::<JoinRequest>(name, params)?),
                true,
            ),
            _ => return Ok((CanVerbGate::Unchecked, Vec::new())),
        };
        match admission {
            Ok(()) => Ok((CanVerbGate::Auto, Vec::new())),
            // A store that fails the read fails the answer, as it would fail
            // the call.
            Err(error) if error.code == MEMORY_CODE_INTERNAL => Err(error),
            Err(error) if persons_act && !person => Ok((CanVerbGate::Person, vec![error.message])),
            Err(error) => Ok((CanVerbGate::Refused, vec![error.message])),
        }
    }
}

/// `params` as `verb`'s input, checked as the verb's own call checks it.
fn verb_input<T: serde::de::DeserializeOwned>(
    verb: &str,
    params: &serde_json::Value,
) -> MemoryResult<T> {
    crate::verbs::validate_input(verb, params)?;
    serde_json::from_value(params.clone()).map_err(|error| {
        MemoryError::bad_request_with(
            format!("can({{verb}}) params are not {verb}'s input: {error}"),
            &["Pass params exactly as the verb's own call takes them."],
        )
    })
}
