//! `vault.data_key.generation.propose`: an agent whose live owner Grant lists
//! the verb asks each owner to start a new vault data-key generation. One
//! inbox ask per owner and generation; the owner's act settles it. It changes
//! no key; the act itself stays the owner's.

use crate::memory::{Memory, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::data_key_generation::DataKeyGenerationProposeRequest;

/// `vault.data_key.generation.propose`: an agent asks the owners to start a
/// new data-key generation (DATAKEY-GEN-WHO = C); it changes no key.
pub fn propose_data_key_generation(
    memory: &Memory<'_>,
    input: DataKeyGenerationProposeRequest,
) -> MemoryResult<crate::world_keys::DataKeyGenerationProposal> {
    memory
        .vault()
        .propose_data_key_generation_as_agent(memory, input.reason.as_deref())
}
