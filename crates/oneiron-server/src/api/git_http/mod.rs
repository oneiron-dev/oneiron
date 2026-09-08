//! Git smart-HTTP routes (ARCH-0068 Phase A, ONE-1908).
//!
//! Protocol only. This module owns routes, the auth gate, and the streaming
//! bridge onto [`oneiron::origin::smart_http`]; it owns no landing logic and no
//! publication logic, so the object-storage and publication routes that come
//! next nest beside it without rework.
//!
//! # Credentials on the wire
//!
//! One credential travels, and it is the one the rest of the server already
//! speaks: `Authorization: Bearer`. A stock git client carries it with
//!
//! ```text
//! git -c http.extraHeader="Authorization: Bearer <token>" clone http://127.0.0.1:7777/git/demo.git
//! ```
//!
//! That is client configuration, not a protocol change. An unauthenticated
//! `info/refs` answers `401` with a bearer challenge, which is what makes a
//! stock client ask for credentials instead of failing opaquely.
//!
//! # The gates
//!
//! | Route | Gate |
//! |---|---|
//! | `GET  /git/{repo}/info/refs?service=git-upload-pack` | `Read` |
//! | `GET  /git/{repo}/info/refs?service=git-receive-pack` | `Write` + a registered `principal_ref` |
//! | `POST /git/{repo}/git-upload-pack` | `Read` |
//! | `POST /git/{repo}/git-receive-pack` | `Write` + a registered `principal_ref` |
//!
//! RC4 is the second row of that table read twice: a push needs a real bearer
//! that resolves to a *registered principal*, and it needs it on `127.0.0.1`
//! exactly as much as anywhere else. The unauthenticated-dev escape hatch is
//! untouched here and cannot admit a push, because the identity it mints
//! carries no `principal_ref` — a route address is not a principal, so no
//! loopback branch exists to take.
//!
//! The first two rows are told apart by the `service=` parameter, so that
//! parameter is canonicalized before anything reads it: exactly one is
//! required, a query naming zero or several is `400`, and the backend is handed
//! the single value the gate decided about rather than the client's query
//! string. The gate and the advertisement can therefore never be about
//! different services.
//!
//! # Streaming
//!
//! Request bodies stream into the backend and response bodies stream back out,
//! one bounded chunk at a time. Nothing is buffered whole, no size cap and no
//! rate cap is added here, and a large pack rides through without ever being

mod gate;
mod routes;
mod serve;
mod status_codec;
#[cfg(test)]
mod tests_auth;
#[cfg(test)]
mod tests_push;

pub(crate) use self::routes::git_http_routes;
