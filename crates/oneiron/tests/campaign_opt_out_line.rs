//! Every campaign email carries a plain opt-out line (L3-02).
//!
//! Canon ARCH-0059 #opt-out (owner, 2026-10-15): "A genuine 1:1 mail carries
//! a plain opt-out line in its body instead, because the header marks mail
//! as bulk." Engine ruling L3-02-SEND-MODE-SCOPE = A (13 Nov 21:23): each
//! campaign email send, on the gmail and the stalwart branches, appends one
//! fixed line to the step body before the send plan or native message is
//! sealed: "If you would rather not hear from me again, reply STOP to
//! <sender address> and I will not write to you again." It is deterministic,
//! so a retry seals the same content ref. The reader's STOP reply is the
//! built STOP-reply path's opt-out.
//!
//! Before this, a campaign email carried no opt-out at all: no bulk header
//! (the sender freezes empty hygiene headers) and no line.

// The sealing is crate-private; `oneiron::test_doors` reaches it, and only
// the test command's `--cfg oneiron_test_support` compiles that door.
#![cfg(oneiron_test_support)]

use oneiron::channel_identity_provider::gmail::{
    GmailDelegatedAdapter, GmailDelegatedAdapterConfig,
};
use oneiron::test_doors::campaign_opt_out_line::{seal_gmail, seal_native_mail};

const SUBJECT: &str = "A short call next week?";
const RECIPIENT: &str = "yuki@example.org";
const STEP_BODY: &str = "Hi Yuki,\n\nYour note on the garden survey was useful. Would a short call next week suit you?\n\nOwen\n\n";
const COMPOSED_AT: u64 = 1_790_000_000;

/// The ruled line, naming `sender_address`.
fn opt_out_line(sender_address: &str) -> String {
    format!(
        "If you would rather not hear from me again, reply STOP to {sender_address} and I will not write to you again."
    )
}

/// The body each branch must send: the step body without its trailing
/// whitespace, one blank line, then the line.
fn expected_body(sender_address: &str) -> String {
    format!(
        "{}\n\n{}",
        STEP_BODY.trim_end(),
        opt_out_line(sender_address)
    )
}

#[test]
fn a_campaign_gmail_send_ends_with_the_opt_out_line_and_a_retry_seals_the_same_ref() {
    let mailbox = "owen@example.com";
    let adapter = GmailDelegatedAdapter::new(
        GmailDelegatedAdapterConfig::new(mailbox, "custody-owen-mailbox")
            .expect("a member mailbox config"),
    );
    let sealed = seal_gmail(
        &adapter,
        "campaign-intent-1",
        RECIPIENT,
        SUBJECT,
        STEP_BODY,
        COMPOSED_AT,
    )
    .expect("the campaign gmail plan seals");
    assert!(
        sealed.body_text.ends_with(&opt_out_line(mailbox)),
        "the sealed gmail body must end with the opt-out line naming the member mailbox; got {:?}",
        sealed.body_text
    );
    assert_eq!(sealed.body_text, expected_body(mailbox));

    let retry = seal_gmail(
        &adapter,
        "campaign-intent-1",
        RECIPIENT,
        SUBJECT,
        STEP_BODY,
        COMPOSED_AT,
    )
    .expect("the retry seals");
    assert_eq!(
        retry.content_ref, sealed.content_ref,
        "a retry of the same send must seal the same plan ref"
    );
    assert_eq!(retry, sealed);
}

#[test]
fn a_campaign_native_mail_send_ends_with_the_opt_out_line_and_a_retry_seals_the_same_ref() {
    let sender_address = "owen@mail.example.test";
    let sealed = seal_native_mail(RECIPIENT, SUBJECT, STEP_BODY, sender_address)
        .expect("the campaign native message seals");
    assert!(
        sealed.body_text.ends_with(&opt_out_line(sender_address)),
        "the sealed native mail text must end with the opt-out line naming the sender's own address; got {:?}",
        sealed.body_text
    );
    assert_eq!(sealed.body_text, expected_body(sender_address));

    let retry =
        seal_native_mail(RECIPIENT, SUBJECT, STEP_BODY, sender_address).expect("the retry seals");
    assert_eq!(
        retry.content_ref, sealed.content_ref,
        "a retry of the same send must seal the same message ref"
    );
    assert_eq!(retry, sealed);
}
