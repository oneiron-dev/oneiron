//! A structural put's one content write: owner and marker checks, then body, birth, edges, text.

use super::inputs::ResolvedEdge;
use super::*;

/// What a structural put lands, resolved before its write opens.
pub(super) struct StructuralWrite {
    pub(super) id: crate::EntityId,
    pub(super) type_byte: u8,
    pub(super) occurred: TimeRange,
    pub(super) learned_at: u64,
    pub(super) data: Vec<u8>,
    pub(super) sources: Vec<(crate::EntityId, f32)>,
    pub(super) resolved_edges: Vec<ResolvedEdge>,
    pub(super) text_fields: Vec<(String, String)>,
    pub(super) birth: Option<RowBirth>,
}

impl Memory<'_> {
    /// Inside the put's write transaction; `true` means a hard-delete marker
    /// refused the id.
    pub(super) fn write_structural_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
        write: StructuralWrite,
    ) -> MemoryResult<(bool, crate::agent_def::AgentDefinitionWriteReceipts)> {
        let StructuralWrite {
            id,
            type_byte,
            occurred,
            learned_at,
            data,
            sources,
            resolved_edges,
            text_fields,
            birth,
        } = write;
        // An actor-capable PERSON is still an owner verb; the content
        // transaction does not substitute for that domain authority. A human
        // proves the owner binding as today; an agent mints one only while
        // the owner's setting `memory.person.agent_may_mint` is on and its
        // own live Grant names this put's verb (restriction wave 7, C27),
        // checked in this same write transaction. MACHINE stays refused for
        // everyone at admission.
        if type_byte == ENTITY_TYPE_PERSON {
            match self.actor_class {
                EdgeActorClass::Human => {
                    verify_owner_actor_binding_in_txn(self.vault, content.read(), self.actor)?;
                }
                EdgeActorClass::Agent => {
                    self.admit_person_mint_in_txn(content.read())?;
                }
                _ => {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!(
                            "actor class {} may not mint PERSON entities; PERSON is actor-capable",
                            self.actor_class.gate_actor_class(),
                        ),
                        &[
                            "PERSON entities rebind as human/agent actors; only the owner mints them.",
                            "Bind a verified human-class owner actor key to create people.",
                        ],
                    ));
                }
            }
        }
        if self
            .vault
            .local_hard_delete_marker_exists_in_txn(content.read(), &id)?
        {
            return Ok((
                true,
                crate::agent_def::AgentDefinitionWriteReceipts::default(),
            ));
        }
        ensure_structural_create_in_txn(self.vault, content.read(), &id)?;
        guard(content.read())?;
        let mut batch = if sources.is_empty() {
            self.vault
                .batch_in()
                .put(&id, type_byte, occurred, learned_at, &data)
        } else {
            self.vault
                .batch_in()
                .asset_text_birth(&id, occurred, learned_at, &data, &sources)
        };
        // An agent's new AGENT_DEF is held to its own slice (ARCH-0053:20).
        batch = batch.made_by(&id, birth).authored_through(
            &self.write_actor(),
            "vault.structural.put",
            content.lane_actor_key(),
        );
        for (kind, target, weight) in &resolved_edges {
            batch = batch.edge(&id, *kind, target, *weight);
        }
        if !text_fields.is_empty() {
            let fields: Vec<(&str, &str)> = text_fields
                .iter()
                .map(|(field, value)| (field.as_str(), value.as_str()))
                .collect();
            batch = batch.text(&id, &fields);
        }
        // What the author writer makes of an agent's AGENT_DEF, for the receipt.
        let written = batch.agent_definition_write_receipts();
        content.apply_batch(batch)?;
        Ok((false, written))
    }

    /// The agent arm of the PERSON mint (restriction wave 7, C27), in the
    /// put's own write transaction `txn`: the owner's setting
    /// `memory.person.agent_may_mint` reads true, and one live Grant a live
    /// owner gave this agent confers now and lists `vault.structural.put`
    /// by name — the one verb row that calls `put_structural`
    /// (`scripts/sdk/verbs/vault.structural.put.json`), so the standing
    /// check names it directly. The credential the agent presented must
    /// still be live. A key-off agent keeps today's refusal, with the key
    /// that now opens it added to its hints.
    fn admit_person_mint_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        crate::memory::verify_actor_binding_in_txn(self.vault, txn, self.actor, self.actor_class)?;
        if let Some(slip) = self.presented_credential()
            && !self.vault.capability_slip_is_live_in_txn(txn, slip)?
        {
            return Err(person_mint_refused(
                "the caller's credential is no longer live",
            ));
        }
        let key_on = crate::memory::structural::setting_keys::PERSON_AGENT_MAY_MINT
            .read_in_txn(self.vault, txn, &[], None)?
            .value;
        if !key_on {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "actor class {} may not mint PERSON entities; PERSON is actor-capable",
                    self.actor_class.gate_actor_class(),
                ),
                &[
                    "PERSON entities rebind as human/agent actors; only the owner mints them.",
                    "Bind a verified human-class owner actor key to create people.",
                    "Or have the owner turn on memory.person.agent_may_mint and grant this agent vault.structural.put by name.",
                ],
            ));
        }
        let standing = crate::authority::principal_standing_or_lapse_in_txn(
            self.vault,
            txn,
            self.actor,
            self.actor_class,
            "vault.structural.put",
        )?;
        match standing.map(|standing| standing.grant) {
            Ok(Some(_)) => Ok(()),
            Err(crate::authority::NoStanding::PactStandingLapsed) => {
                Err(person_mint_refused(crate::authority::PACT_STANDING_LAPSED))
            }
            Ok(None) | Err(crate::authority::NoStanding::NotStanding) => Err(person_mint_refused(
                "no live Grant from a live owner names this agent and lists the verb",
            )),
        }
    }
}

/// The PERSON mint's refusal of an agent caller it does not admit.
fn person_mint_refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "vault.structural.put takes the vault owner's own proof, or an agent's own Grant that names it while the owner's setting memory.person.agent_may_mint is on: {why}"
        ),
        &[
            "Call with your own owner credential, or have the owner turn on memory.person.agent_may_mint and grant this agent the verb by name.",
        ],
    )
}
