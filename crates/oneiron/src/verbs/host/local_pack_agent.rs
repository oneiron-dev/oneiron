//! `vault.packs.put` from a resident agent's own handle (ARCH-0080 §7): the
//! agent replaces the `local` pack and binds the hooks it wrote as its own.
use super::{PackPutReceipt, PackPutRequest};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// `vault.packs.put` as the handle's own agent
/// ([`crate::Vault::put_local_pack_as_agent`]): each hook whose body the
/// agent wrote binds stamped with the agent, at its own ceiling. A caller
/// that is no agent is refused, and nothing is written.
pub fn put_local_pack_as_agent(
    memory: &Memory<'_>,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    if memory.actor_class() != crate::EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "an agent's vault.packs.put takes the agent's own handle",
            &["Call vault.packs.put with the owner's own credential."],
        ));
    }
    let agent = memory.write_actor();
    Ok(memory
        .vault()
        .put_local_pack_as_agent(&agent, input.into_files()?)?
        .into())
}
