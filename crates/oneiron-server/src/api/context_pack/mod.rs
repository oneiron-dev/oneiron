//! Core context-pack assembly: POST /v1/core/context-pack validates the request, runs
//! scoped retrieval through the shared pipeline, and projects the wire response.

mod audience;
mod companion_assembly;
mod controls;
mod interlocutor;
mod media_query;
mod reader;
mod resolve;
mod response;

pub(crate) use self::audience::*;
pub(crate) use self::companion_assembly::*;
pub(crate) use self::controls::*;
pub(crate) use self::interlocutor::*;
pub(crate) use self::media_query::*;
pub(crate) use self::reader::*;
pub(crate) use self::resolve::*;
pub(crate) use self::response::*;
