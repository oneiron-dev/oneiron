//! The `retrieval.vector_evidence` row (its value and item domain: the parent module). It sits
//! in a file named `setting_keys.rs`, the only name build.rs reads catalogue rows from.

use super::{OwnerEvidenceFloors, check_space_row, is_embedding_space};
use crate::setting::{ItemDomain, Kind, SettingSync};

crate::setting::setting_keys! {
    /// The owner's no-match floors for one embedding space (EMBEDDER-ENDPOINT-VECTOR-FLOORS;
    /// Engine ANSWER 27 Nov 01:45): `{floor, strong}`, two cosine similarities with
    /// `0 <= floor <= strong <= 1`, refused outside that, never clamped. One item per space,
    /// named by its model id, `org/name@revision`, as the vault's vectors are pinned to it. Set,
    /// the pair judges every score in that space, of every kind, in place of the host's floors:
    /// with no keyword hit, a context pack whose every vector score sits under `floor` is
    /// withheld, and so is one whose top hit sits under `strong` and barely leads the next.
    /// Unset, or a row that does not read: the host's floors (its embedder's measured pair, else
    /// the engine's 0.30/0.50). A row for a space the vault's vectors are not in judges nothing
    /// until they are. Each row is one space's own: a row with no item is refused, since it
    /// would judge every space with no row of its own. Only the owner sets it: an agent's change
    /// waits on the owner's answer to that change, and the owner's standing approval does not
    /// cover it.
    pub(crate) VECTOR_EVIDENCE: OwnerEvidenceFloors = "retrieval.vector_evidence" {
        kind: Kind::new(OwnerEvidenceFloors::unset).strictest(OwnerEvidenceFloors::unset),
        item: Some(ItemDomain { name: "embedding spaces", admits: is_embedding_space }),
        sync: SettingSync::Vault,
        on_change: Some(check_space_row),
        standing_approval: false,
    };
}
