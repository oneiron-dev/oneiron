//! Fix list row 20852: an IMAP or mbox landing reads From, Reply-To, To and
//! Cc from the message's whole header block. A header parse keeps only the
//! first 1,024 fields, so before this fix a Reply-To after them was lost and
//! a reply to the message went to From.
//!
//! Reaches the two crate-private landings through the test door
//! `oneiron::test_doors::mail_landing`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test mail_late_address_headers`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::mail_landing::{imap_landed_reply_to, mbox_landed_reply_to};

/// More filler fields than a header parse keeps.
const FILLER_FIELDS: usize = 1_100;

/// A message whose Reply-To comes after `FILLER_FIELDS` other fields.
fn late_reply_to_message() -> Vec<u8> {
    let mut raw = String::from(
        "From: Owen <owen@example.com>\r\nTo: yuki@example.com\r\nSubject: late reply-to\r\n\
         Message-ID: <late-reply-to@example.com>\r\n",
    );
    for field in 0..FILLER_FIELDS {
        raw.push_str(&format!("X-Filler-{field}: filler\r\n"));
    }
    raw.push_str("Reply-To: late@example.com\r\n\r\nbody\r\n");
    raw.into_bytes()
}

#[test]
fn imap_late_reply_to_lands() {
    assert_eq!(
        imap_landed_reply_to(&late_reply_to_message()),
        vec!["late@example.com".to_owned()]
    );
}

#[test]
fn mbox_late_reply_to_lands() {
    assert_eq!(
        mbox_landed_reply_to(&late_reply_to_message()),
        Some(vec!["late@example.com".to_owned()])
    );
}
