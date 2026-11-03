//! FIX 595 sequential DOCX revision projection: reserved module shell.
//!
//! The bytes-chained projection is BLOCKED (see
//! `lanes/l12/muse/BLOCKED-595-PROJECTION.md` in the vibe-build dir):
//! re-parsing an intermediate package renumbers its block ids, so later
//! groups' id-addressed diffs would hit the wrong blocks. This empty module
//! exists only so the `mod revision_window;` wiring compiles; the Engine
//! redesign replaces it with the real implementation or removes it.
