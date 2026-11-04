//! Delivery-window vocabulary of the oneiron engine: the quiet-hours and
//! channel claim keys, decisions and ladder rungs, and the outbound schedule
//! context. The `oneiron` crate keeps claim decoding and evaluation, and
//! reaches these modules at their old `delivery_window::{types,
//! schedule_context}` paths.

pub mod delivery_window;
