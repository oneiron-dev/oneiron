//! The member peer whose first-party update an import lands
//! (ROOM-BODY-REPLICA-SETTINGS). Window admission judged each room body the
//! update brings against the row this vault held then; the entity door
//! judges it again in its writer transaction, against the row the put
//! replaces, as this span's sender. Only a federation import of a member's
//! update opens one: own-device replay names no sender and stays trust-blind
//! (ARCH-0040:261).
//!
//! The writer's refusal outlives no import: a cold replay of the window
//! names no sender. So the span also notes that its writer refused a room
//! body, and the import that opened it lands nothing of its update in the
//! window's document ([`member_body_refused`]).

use std::cell::{Cell, RefCell};
use std::path::PathBuf;

use crate::{EntityId, Vault};

thread_local! {
    static MEMBER_SENDER: RefCell<Option<MemberSender>> = const { RefCell::new(None) };
}

/// One import's member sender, the vault the import lands in, and whether
/// the writer refused a room body the import brought.
struct MemberSender {
    vault: PathBuf,
    sender: EntityId,
    refused: Cell<bool>,
}

/// Puts back the span an outer import installed, on every exit.
struct Restore(Option<MemberSender>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        MEMBER_SENDER.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Runs `import`, which lands a member peer's update in `vault`, while the
/// entity doors on this thread judge each room body it brings as
/// `sender`'s. With no sender, no door `import` runs names one, whatever
/// import encloses it.
pub(in crate::sync) fn with_member_sender<T>(
    vault: &Vault,
    sender: Option<EntityId>,
    import: impl FnOnce() -> T,
) -> T {
    let span = sender.map(|sender| MemberSender {
        vault: vault.store.env.path().to_path_buf(),
        sender,
        refused: Cell::new(false),
    });
    let _restore =
        Restore(MEMBER_SENDER.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), span)));
    import()
}

/// The member sender of the import landing in `vault` on this thread, if one.
pub(super) fn member_sender(vault: &Vault) -> Option<EntityId> {
    MEMBER_SENDER.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|span| span.vault.as_path() == vault.store.env.path())
            .map(|span| span.sender)
    })
}

/// Notes that the writer refused a room body of the member import landing in
/// `vault` on this thread.
pub(super) fn note_member_body_refused(vault: &Vault) {
    MEMBER_SENDER.with(|slot| {
        if let Some(span) = slot
            .borrow()
            .as_ref()
            .filter(|span| span.vault.as_path() == vault.store.env.path())
        {
            span.refused.set(true);
        }
    });
}

/// Whether the writer refused a room body of the member import landing in
/// `vault` on this thread. The import then keeps none of its update in the
/// window's document: the refused carrier would otherwise be persisted, sent
/// on, and landed by a cold replay that names no sender.
pub(in crate::sync) fn member_body_refused(vault: &Vault) -> bool {
    MEMBER_SENDER.with(|slot| {
        slot.borrow().as_ref().is_some_and(|span| {
            span.vault.as_path() == vault.store.env.path() && span.refused.get()
        })
    })
}
