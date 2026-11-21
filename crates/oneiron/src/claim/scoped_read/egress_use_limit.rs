//! The owner read's source use-limit conjunct (FIX 1496 S8), asked by each
//! door a row leaves this vault by, so an owner archive or the owner's
//! devices never carry a row the owner's own read withholds (FIX
//! EGRESS-CARRIES-ROWS-DERIVED-FROM-USE-LIMITED-RECORDS).

use super::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The actor the scoped read that carries the egress use-limit walk names.
/// Its key reads no row; the walk reads stored lineage and use limits only.
const EGRESS_USE_LIMIT_WALK_ACTOR: &str = "egress-use-limit-walk";

impl crate::vault::Vault {
    /// Whether `id` itself, or any record the words of its stored revision
    /// came from, carries a standing record use limit
    /// ([`crate::store::legal_hold::use_limit_in_txn`]): the question a door
    /// asks before a row leaves this vault, for the owner's archive or
    /// devices too. A SUMMARY or PSYCH_PROFILE of a use-limited CLAIM stays
    /// home with the claim. The sources are judged by the owner's own read's
    /// walk (`ScopedRead::owner_sources_use_limited_in`) on base, so the
    /// door withholds exactly what that read withholds. A vault with no use
    /// limit answers from two table probes; a row this vault stores no
    /// revision of answers by its own limit alone.
    ///
    /// # Errors
    ///
    /// Storage failures, a stored row with no readable header, and a word
    /// source the owner's read cannot judge either.
    pub(crate) fn row_or_word_source_use_limited_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if !crate::store::legal_hold::any_record_use_limit_in_txn(&self.store, txn)? {
            return Ok(false);
        }
        if crate::store::legal_hold::use_limit_in_txn(&self.store, txn, id)?.is_some() {
            return Ok(true);
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
        else {
            return Ok(false);
        };
        // The walk asks no key: a key that reads no row carries it, so
        // nothing it reaches can widen through the key.
        let key = ScopedReadActorKey::read_nothing(
            EGRESS_USE_LIMIT_WALK_ACTOR,
            EdgeActorClass::System.gate_actor_class(),
        )
        .ok_or_else(|| Error::InvalidConfig("the egress use-limit walk keys no read".into()))?;
        self.scoped_read(key)
            .owner_sources_use_limited_in(txn, id, &raw)
    }
}
