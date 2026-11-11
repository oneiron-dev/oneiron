//! One string member of a call's args its host holds as a file, outside the
//! JSON args, until a verb hook would read them (FIX 22074, Engine ruling
//! E1 = C). A host decodes a large `content_base64` into a file before the
//! call and hands the row its args with that member empty. The pre chain of
//! the call takes the file first, before any nested call of its run can
//! reach a chain on this thread. A call no hook is live on passes through
//! with its args untouched, and its row reads the member from the file. A
//! call a hook is live on gets the member's string back in its args before
//! any hook reads them, and runs on those args as JSON from then on.

use std::cell::RefCell;
use std::fs::File;
use std::io::{Seek, SeekFrom};

use serde_json::Value;

thread_local! {
    static HELD: RefCell<Option<HeldMember>> = const { RefCell::new(None) };
}

/// A string member a host holds as the file of the bytes the string
/// encodes in standard base64.
pub(crate) struct HeldMember {
    name: &'static str,
    file: File,
}

/// What keeps a held member for the next pre chain this thread runs; the
/// member goes when it drops, if no chain took it.
pub(crate) struct HeldMemberGuard(());

impl Drop for HeldMemberGuard {
    fn drop(&mut self) {
        HELD.with(|held| held.borrow_mut().take());
    }
}

/// Holds member `name` as `file` for the next pre chain this thread runs.
pub(crate) fn hold_member(name: &'static str, file: File) -> HeldMemberGuard {
    HELD.with(|held| *held.borrow_mut() = Some(HeldMember { name, file }));
    HeldMemberGuard(())
}

/// Runs `run` with member `name` held as `file` for the first pre chain it
/// runs on this thread: a host that runs a row's pre chain itself, not
/// through the engine's row boundary, holds the member there (FIX 22074).
/// The member goes when `run` returns, taken or not.
pub fn with_held_member<R>(name: &'static str, file: File, run: impl FnOnce() -> R) -> R {
    let _held = hold_member(name, file);
    run()
}

/// The member held for this call, taken: no other chain meets it.
pub(super) fn take() -> Option<HeldMember> {
    HELD.with(|held| held.borrow_mut().take())
}

impl HeldMember {
    /// Puts the member's string back in `args`: the file's bytes in
    /// standard base64, the string the caller sent.
    ///
    /// # Errors
    ///
    /// The file's read errors.
    pub(super) fn restore(mut self, args: &mut Value) -> crate::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut text =
            base64::write::EncoderStringWriter::new(&base64::engine::general_purpose::STANDARD);
        std::io::copy(&mut self.file, &mut text)?;
        if let Some(members) = args.as_object_mut() {
            members.insert(self.name.to_owned(), Value::String(text.into_inner()));
        }
        Ok(())
    }
}
