//! `vault.receipts`'s input and its page (FIX 10186): any positive limit,
//! requested on either ledger, with `after` continuing a page's receipts.

pub use crate::memory::VaultReceiptsPage;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::receipts_page::VaultReceiptsRequest;
