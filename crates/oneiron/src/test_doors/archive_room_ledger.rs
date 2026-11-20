//! Doors for `tests/archive_import_owner_installs_room_membership.rs` (REVIEW-9446 P1-3,
//! P1-4, round 2 P1-3 to P1-5): a source room ledger the membership door never writes, a
//! ledger with no room record beside it, or a leader chat room opened without projects, so
//! the source's whole-vault archive carries one. Not API.

use crate::conversation::{ConversationBody, ConversationKind};
use crate::{EntityId, Error, Result, TimeRange, Vault, WriteActor};

/// Deletes room `room`'s ledger revision row and keeps its rows.
///
/// # Errors
///
/// The store's.
pub fn drop_room_ledger_sequence(vault: &Vault, room: EntityId) -> Result<()> {
    crate::conversation::archive_restore::ledger_test_support::drop_sequence(vault, room)
}

/// Copies room `room`'s ledger rows and revision row from `from` into `to`, byte for byte as
/// the ledger codec writes them, with no room record beside them on `to`.
///
/// # Errors
///
/// The stores'.
pub fn copy_room_ledger(from: &Vault, to: &Vault, room: EntityId) -> Result<()> {
    crate::conversation::archive_restore::ledger_test_support::copy_ledger(from, to, room)
}

/// Opens room `room` as the leader chat of `persons` for `projects`, each PERSON speaking as
/// itself, as the project door does: the binding goes under this vault's private leader chat
/// key and the Direct room through the room creator as `actor`, in one write transaction. The
/// project leader and rule checks are skipped, so the fixture needs no projects.
///
/// # Errors
///
/// The room creator's.
pub fn open_bound_leader_chat(
    vault: &Vault,
    room: EntityId,
    projects: [EntityId; 2],
    persons: [EntityId; 2],
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    let chat = crate::workspace_roster::LeaderChat {
        projects,
        actors: persons,
        persons: persons.map(Some),
    };
    vault.with_write_txn_grouped(|txn| {
        let bytes =
            crate::workspace_roster::project::bind_leader_chat_in_txn(vault, txn, room, &chat)?;
        let mut body = ConversationBody {
            kind: ConversationKind::Direct,
            member_ids: persons.to_vec(),
            ..Default::default()
        };
        body.extra.insert(
            crate::workspace_roster::LEADER_CHAT_FIELD.to_owned(),
            rmp_serde::from_slice(&bytes)
                .map_err(|_| Error::InvariantViolation("leader chat binding decodes"))?,
        );
        crate::conversation::create_in_txn(
            vault,
            txn,
            room,
            &body,
            actor,
            TimeRange { start: at, end: at },
            at,
            &[],
        )
    })
}

/// Rewrites row `ordinal` of room `room`'s ledger with `visible_from`.
///
/// # Errors
///
/// The store's, or `InvariantViolation` when the room holds no such row.
pub fn set_room_ledger_row_visible_from(
    vault: &Vault,
    room: EntityId,
    ordinal: u64,
    visible_from: Option<u64>,
) -> Result<()> {
    crate::conversation::archive_restore::ledger_test_support::set_row_visible_from(
        vault,
        room,
        ordinal,
        visible_from,
    )
}

/// Keeps on `vault` an inert retained copy of a `source_table` row with key `source_key` and
/// value `source_value`, unchecked against the table, as an import of an archive carrying it
/// would (REVIEW-9739 P1-2: a malformed copy of a room's ledger row).
///
/// # Errors
///
/// The store's.
pub fn retain_inert_side_row(
    vault: &Vault,
    source_table: &str,
    source_key: Vec<u8>,
    source_value: Vec<u8>,
) -> Result<()> {
    crate::batch::export::archive_retained_side_rows::retain_inert_copy_for_test(
        vault,
        source_table,
        source_key,
        source_value,
    )
}
