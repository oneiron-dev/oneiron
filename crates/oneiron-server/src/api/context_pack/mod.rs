//! Core context-pack assembly: POST /v1/core/context-pack validates the request, runs
//! scoped retrieval through the shared pipeline, and projects the wire response.

mod companion_assembly;
mod controls;
mod interlocutor;
mod resolve;
mod response;

pub(crate) use self::companion_assembly::*;
pub(crate) use self::controls::*;
pub(crate) use self::interlocutor::*;
pub(crate) use self::resolve::*;
pub(crate) use self::response::*;
