//! What an answer holds (a deck preview's renderer lease and turn), kept until the answer is encoded.
//! `until_encoded`, `keeping` and `KeptUntilEncoded` are its call surface (FIX 8238).
//! The kept values are their owners' own; this module only moves them to the encode point.

use std::any::Any;
use std::cell::RefCell;
use std::future::Future;

tokio::task_local! {
    /// What the answers this task encodes keep, until the task's answer is
    /// encoded.
    static KEPT: RefCell<Vec<Box<dyn Any + Send>>>;
}

/// Runs `answer`, a door's whole reply up to its encoded bytes, keeping
/// until it returns every value a [`KeptUntilEncoded`] handed over meanwhile.
/// No deadline and no count: what is kept is dropped when the reply is.
pub(crate) async fn until_encoded<F: Future>(answer: F) -> F::Output {
    KEPT.scope(RefCell::new(Vec::new()), answer).await
}

/// [`until_encoded`] for an answer encoded past this task, beside what it
/// kept: the caller drops the [`Kept`] once it has handed the answer on.
pub(crate) async fn keeping<F: Future>(answer: F) -> (F::Output, Kept) {
    KEPT.scope(RefCell::new(Vec::new()), async {
        let output = answer.await;
        let kept = KEPT.with(|kept| std::mem::take(&mut *kept.borrow_mut()));
        (output, Kept { _values: kept })
    })
    .await
}

/// The values an answer's [`keeping`] kept, dropped with it.
pub(crate) struct Kept {
    _values: Vec<Box<dyn Any + Send>>,
}

/// A value an answer holds while it is encoded: dropped inside
/// [`until_encoded`] or [`keeping`], it moves to that scope and lives until
/// the scope ends; dropped anywhere else, it drops then, as before.
pub(crate) struct KeptUntilEncoded<T: Send + 'static>(Option<T>);

impl<T: Send + 'static> KeptUntilEncoded<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T: Send + 'static> Drop for KeptUntilEncoded<T> {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            // Outside any scope the closure, and the value with it, drops
            // here.
            let _ = KEPT.try_with(move |kept| {
                if let Ok(mut kept) = kept.try_borrow_mut() {
                    kept.push(Box::new(value));
                }
            });
        }
    }
}
