//! A structural put's refusals: CLAIM, MACHINE, NOTE, MESSAGE, a non-owner's PERSON, a non-object body.

use super::*;

impl Memory<'_> {
    pub(super) fn admit_structural_kind(
        &self,
        type_byte: u8,
        input: &StructuralPutInput,
    ) -> MemoryResult<()> {
        if type_byte == ENTITY_TYPE_CLAIM {
            return Err(MemoryError::bad_request_with(
                "CLAIM entities cannot be written structurally",
                &["Use vault.commit/vault.claims.upsert so the write gate sees the claim."],
            ));
        }
        if type_byte == ENTITY_TYPE_MACHINE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "MACHINE entities cannot be written through the facade",
                &[
                    "MACHINE is the system-actor class type; minting one would forge an actor.",
                    "System actors are provisioned by the engine host, not the bridge.",
                ],
            ));
        }
        // NOTE bodies carry `author_ref`, and attribution is engine-stamped by
        // construction: a caller who could hand-write the body could forge
        // another actor's take. This broad door has no way to bind one, so it
        // refuses the kind outright rather than validating a body it cannot
        // trust.
        if type_byte == ENTITY_TYPE_NOTE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "NOTE entities cannot be written through the structural door",
                &[
                    "NOTE bodies are actor-attributed; a caller-supplied author_ref would be a forgery.",
                    "Use author_take, which stamps the bound facade actor.",
                ],
            ));
        }
        // ONE-1686 (RT-04): MESSAGE bodies carry the six-axis witness envelope
        // — author, type, content, metadata, visibility, order — and the
        // approval-ceiling door authorizes exactly those axes at the witness
        // write boundary. A caller who could hand-write the body here would
        // author an unattributed `system` row, hide a row, or smuggle a
        // metadata side channel through a door that never asked. Same posture
        // as the NOTE refusal above: this broad door has no envelope to bind,
        // so it refuses the kind rather than validating a body it cannot trust.
        if type_byte == ENTITY_TYPE_MESSAGE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "MESSAGE entities cannot be written through the structural door",
                &[
                    "MESSAGE bodies are gated envelopes; a caller-supplied body would bypass the witness ceiling.",
                    "Use witness, which binds author, type, content, metadata, visibility and order to the acting actor.",
                ],
            ));
        }
        if type_byte == ENTITY_TYPE_PERSON && self.actor_class != EdgeActorClass::Human {
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
        if !input.body.is_object() {
            return Err(MemoryError::bad_request(
                "structural body must be a JSON object",
            ));
        }
        Ok(())
    }
}
