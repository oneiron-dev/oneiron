//! Web acquisition of the oneiron engine. `web_acquisition` holds the fetch
//! and crawl vocabulary (requests, results, errors, hosted-egress refusals)
//! and the `WebAcquisition` trait; `web_fetch` holds the renderer ladder that
//! implements it. The `oneiron` crate re-exports both at their old paths
//! (`oneiron::web_fetch`, `oneiron::memory::web_acquisition`).

pub mod web_acquisition;
pub mod web_fetch;
