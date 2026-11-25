//! The issuer's side of a job that one of the vault's machines runs (pass 33 section 8, the
//! `vault_machine` connector): the `JOB_DISPATCH` and `JOB_OBSERVATION` rows ([`record`]), and
//! the checks before each dispatch and at each step ([`recheck`]). The connector itself, which
//! signs, sends and reads receipts over the mesh, is oneiron-server's
//! `gpu_execution_node::issuer`.

mod recheck;
mod record;
pub(crate) mod tables;

pub use recheck::{DispatchAsk, DispatchRefusal};
pub use record::{BootMark, DispatchClose, DispatchPhase, JobDispatch, JobObservation};
