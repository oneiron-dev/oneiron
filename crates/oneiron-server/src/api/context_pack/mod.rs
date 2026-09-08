//! Core context-pack assembly: POST /v1/core/context-pack validates the request, runs
//! scoped retrieval through the shared pipeline, and projects the wire response.

mod controls;
mod eiri_assembly;
mod interlocutor;
mod resolve;
mod response;

pub(crate) use self::controls::*;
pub(crate) use self::eiri_assembly::*;
pub(crate) use self::interlocutor::*;
pub(crate) use self::resolve::*;
pub(crate) use self::response::*;
