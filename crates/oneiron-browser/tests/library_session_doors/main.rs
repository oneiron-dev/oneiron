//! Holds the browser workflow library's draft, find, retire, retired and run
//! session doors and the solved-run snapshot door
//! (FIX [BROWSER-LIBRARY-SESSION-DOORS-HELD-BY-NO-TEST]).
//! The attached session is real; its Chromium peer and workflow store are fakes.
//! These tests do not prove a real browser's answers or the vault store's
//! filter, order and ownership rules.

#![cfg(all(target_os = "linux", feature = "driver"))]

mod draft;
mod find;
mod retire;
mod retired;
mod run;
mod scripted_chromium;
mod secret_custody;
mod session_fixture;
mod snapshot;
mod workflow_store;
