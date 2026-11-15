pub use crate::channel_identity_provider::stalwart::reputation::NativeMailReputationReport;
pub use crate::channel_identity_provider::stalwart::reputation::NativeMailSignalSource;
pub use crate::channel_identity_provider::stalwart::send::NATIVE_MAIL_MAX_MESSAGE_BYTES;
use reqwest::blocking::Client;
use reqwest::blocking::Response;
use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderValue;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;

pub mod reputation;
pub mod send;
