//! What a terminal attempt left behind (FIX 9578): its durable outputs and
//! the checkpoint frontier it recorded, written with the row that settles.
//! The type lives with the attempt row in [`crate::store::attempt_record`].

pub use crate::store::attempt_record::AttemptTerminalExhaust;
