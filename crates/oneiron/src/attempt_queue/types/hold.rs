//! The pause a paused attempt row is held under (FIX 9579), kept on the row
//! itself rather than read back from its event history, which prunes.

pub(crate) use crate::store::attempt_record::AttemptPause;
