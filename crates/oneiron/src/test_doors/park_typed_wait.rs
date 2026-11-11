//! Doors for `tests/park_typed_wait.rs` (6.5d-1): the head state of a trap chain.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::edge::EdgeKind;
use crate::llm::{DREAMER_TRAP_PREDICATE, DreamerTrapState, TrapRef};
use crate::vault::Vault;

/// The head state of `trap`'s chain: the state the newest superseding record carries.
///
/// Walks inbound `Supersedes` edges from the anchor (at most 64 hops, the trap walk cap) and reads
/// only the head claim's `state`, so a waiting trap and a consumed one tell apart.
///
/// # Errors
/// Storage, a missing or non-trap head, a branched chain, or an unknown state.
#[doc(hidden)]
pub fn trap_state(vault: &Vault, trap: &TrapRef) -> Result<DreamerTrapState> {
    let txn = vault.store.env.read_txn()?;
    let mut current = trap.trap_claim_id;
    for _ in 0..64 {
        let mut edges = crate::ports::EdgeStoreRead::port_edges(
            &vault.store,
            &txn,
            &current,
            crate::ports::EdgeDirection::In,
            Some(EdgeKind::Supersedes),
            None,
        )?;
        let next = edges.next().transpose()?.map(|edge| edge.target);
        if edges.next().transpose()?.is_some() {
            return Err(crate::Error::InvalidClaimBody(
                "trap supersession chain branches",
            ));
        }
        match next {
            Some(next) => current = next,
            None => {
                let body = vault
                    .get_claim_in_txn(&txn, &current)?
                    .ok_or(crate::Error::InvalidClaimBody("trap head claim missing"))?;
                if body.predicate != DREAMER_TRAP_PREDICATE {
                    return Err(crate::Error::InvalidClaimBody(
                        "trap head is not a trap record",
                    ));
                }
                let rmpv::Value::Map(entries) = &body.value else {
                    return Err(crate::Error::InvalidClaimBody(
                        "trap claim value is not a map",
                    ));
                };
                for (key, value) in entries {
                    if key.as_str() == Some("state") {
                        let name = value
                            .as_str()
                            .ok_or(crate::Error::InvalidClaimBody("trap state is not a string"))?;
                        return DreamerTrapState::parse(name)
                            .ok_or(crate::Error::InvalidClaimBody("unknown trap state"));
                    }
                }
                return Err(crate::Error::InvalidClaimBody(
                    "trap claim value has no state",
                ));
            }
        }
    }
    Err(crate::Error::InvalidClaimBody(
        "trap supersession chain too deep",
    ))
}
