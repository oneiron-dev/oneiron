//! Door for `tests/off_record_side_row_custody.rs` (FIX 2329,
//! ROOM-LOCAL-CUSTODY): one row of an authored side table, a code run's
//! replay table, written as a code run's checkpoint writes it: on a room's
//! write route, through the vault, which holds the custody door, or through a
//! bare store; and read back in a room or in base. The room's own custody is
//! read by its handles, past the room's close too, and base custody by its
//! records and its known-value index.

use std::sync::Arc;

use crate::error::Result;
use crate::off_record::OffRecordSession;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::session_overlay::SessionOverlay;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// The replay table, read as raw bytes: every masked copy decodes.
const REPLAY_ROWS: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::CODE_RUN_REPLAY);

/// Writes `body` as the replay row of `run` on `session`'s current write
/// route: staged into the room's overlay while the room is off record.
///
/// # Errors
///
/// The side-row wall's refusal, a closing session, or storage errors.
pub fn put_room_replay_row(
    session: &OffRecordSession<'_>,
    run: EntityId,
    body: &[u8],
) -> Result<()> {
    let route = session.write_route()?;
    session.routed_side_txn(&route, |wtxn, _read, write| {
        REPLAY_ROWS.put(&write, wtxn, &run, &body.to_vec())
    })
}

/// Writes `body` as the replay row of `run` through `vault`'s bare store,
/// which holds no custody door and is no room's view.
///
/// # Errors
///
/// The side-row wall's refusal, or storage errors.
pub fn put_bare_store_replay_row(vault: &Vault, run: EntityId, body: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    REPLAY_ROWS.put(&vault.store, &mut wtxn, &run, &body.to_vec())?;
    wtxn.commit()?;
    Ok(())
}

/// Writes `body` as the replay row of `run` through `vault`, whose custody
/// door mints a record for each fresh secret the side-row wall places.
///
/// # Errors
///
/// The side-row wall's refusal, or storage errors.
pub fn put_vault_replay_row(vault: &Vault, run: EntityId, body: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    REPLAY_ROWS.put(vault, &mut wtxn, &run, &body.to_vec())?;
    wtxn.commit()?;
    Ok(())
}

/// The replay row of `run` as `session` reads it, over its overlay and base.
///
/// # Errors
///
/// A participant no longer in the room, or storage errors.
pub fn room_replay_row(session: &OffRecordSession<'_>, run: EntityId) -> Result<Option<Vec<u8>>> {
    session.routed_side_read(|rtxn, read| REPLAY_ROWS.get(&read, rtxn, &run))
}

/// The replay row of `run` in base alone, as a bare store reads it.
///
/// # Errors
///
/// Storage errors.
pub fn base_replay_row(vault: &Vault, run: EntityId) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    REPLAY_ROWS.get(&vault.store, &rtxn, &run)
}

/// An off-record room's own custody (ROOM-LOCAL-CUSTODY), held past the
/// room's close, so a test reads what the close left of it.
pub struct RoomCustody(Arc<SessionOverlay>);

impl RoomCustody {
    /// The custody of the room `session` is a stretch of.
    #[must_use]
    pub fn of(session: &OffRecordSession<'_>) -> Self {
        Self(session.overlay())
    }

    /// The value the room keeps under `handle`: bare (`r1`) or as a row
    /// holds it (`[secret r1]`).
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn secret(&self, handle: &str) -> Result<Option<Vec<u8>>> {
        let bare = handle
            .trim()
            .strip_prefix("[secret ")
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(handle);
        Ok(self.0.room_secret(bare)?.map(|value| value.to_vec()))
    }

    /// How many secrets the room keeps now.
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn count(&self) -> Result<usize> {
        self.0.room_secret_count()
    }
}

/// How many custody records base holds.
///
/// # Errors
///
/// Storage errors.
pub fn vault_custody_record_count(vault: &Vault) -> Result<usize> {
    Ok(vault.entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?.len())
}

/// Whether base's known-value index holds `value`'s fingerprint, whole.
///
/// # Errors
///
/// Storage and custody errors.
pub fn vault_knows_value(vault: &Vault, value: &[u8]) -> Result<bool> {
    Ok(vault
        .known_values_now()?
        .is_some_and(|known| known.is_exact_value(value)))
}

/// Witnesses one user message saying `words` into `session` as `actor`,
/// as a participant's message lands in the room's overlay: the turn it
/// opens.
///
/// # Errors
///
/// The witness's refusal, as text.
pub fn say_in_room(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    actor: EntityId,
    words: &str,
) -> std::result::Result<EntityId, String> {
    let receipt = vault
        .memory(actor, crate::EdgeActorClass::Human)
        .witness_into_session(
            session,
            &crate::memory::WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "utterance".to_owned(),
                    content: words.to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    parts: None,
                    quote: None,
                }],
                occurred_at: 1000,
                thread_audience: None,
                project: None,
                assertions: Default::default(),
            },
            None,
            None,
        )
        .map_err(|error| format!("the room refused the message: {error:?}"))?;
    let turn = receipt
        .receipt_ref
        .strip_prefix("witness:")
        .ok_or("the witness receipt names no turn")?;
    EntityId::from_hex(turn).map_err(|error| format!("{error:?}"))
}

/// Whether the body of a base row of `ids` holds `text` in its bytes.
///
/// # Errors
///
/// Storage errors.
pub fn base_rows_hold(vault: &Vault, ids: &[EntityId], text: &str) -> Result<bool> {
    for id in ids {
        if let Some(body) = vault.get(id)?
            && body
                .windows(text.len())
                .any(|window| window == text.as_bytes())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The first vault custody handle (`[secret sc12]`) the body of a base row
/// of `ids` holds, as written.
///
/// # Errors
///
/// Storage errors.
pub fn base_custody_handle_in_rows(vault: &Vault, ids: &[EntityId]) -> Result<Option<String>> {
    for id in ids {
        let Some(body) = vault.get(id)? else {
            continue;
        };
        let text = String::from_utf8_lossy(&body);
        if let Some(start) = text.find("[secret sc")
            && let Some(len) = text[start..].find(']')
        {
            return Ok(Some(text[start..=start + len].to_owned()));
        }
    }
    Ok(None)
}

/// The value the vault custody record `handle` names holds.
///
/// # Errors
///
/// A handle no live record holds, or storage and custody errors.
pub fn vault_custody_value(vault: &Vault, handle: &str) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let (_, id) = crate::secret_custody::handle_record_in_txn(&vault.store, &rtxn, handle)?;
    Ok(
        crate::secret_custody::read_secret_custody_in_txn(&vault.store, &rtxn, &id)?
            .map(|record| record.value_bytes.clone()),
    )
}
