//! An erase in the attribution ledgers (FIX 8265, OF-568 L10; FIX 8988): the
//! rows that name an erased skill or actor drop it in the erase's own write,
//! as a cause row does
//! ([`crate::store::skill_attribution_causes::erase_attribution_cause_entity_in_txn`]).
//!
//! An evidence row keeps its receipt and outcome with its skill or actor
//! slot nil, so a projection that reads it again routes it with no one to
//! name. A judgment charging an erased skill stays, its subject nil (FIX
//! 10640), while every edit proposal naming that skill goes, and the
//! projector, whose cursor is past them, routes neither again. A lapse
//! judgment charging an erased actor stays, its subject nil, and charges
//! no one.
//!
//! The evidence row's erase lives with the row
//! ([`crate::store::skill_attribution_evidence::erase_attribution_evidence_skill_in_txn`]);
//! this module keeps the erase scan the other ledgers share.

pub(crate) use crate::store::side_table_erase_scan::erase_scan_in_txn;
