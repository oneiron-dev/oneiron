//! The owner's opt-out for the feedback destination's HTTPS rule (`feedback.delivery.require_https`;
//! owner principle 16 Nov 00:44: a restriction that is not a correctness fix ships as a good
//! default plus an owner opt-out).
//!
//! With no row a plain-HTTP endpoint off loopback builds no feedback transport, as before, and
//! loopback HTTP still does. The owner's false lets it build. Credentials, a query, a fragment or
//! another scheme never pass whatever the key says. The transport is built the way every send
//! builds it (`HttpFeedbackTransport::for_vault`), so the test reads the rule each send reads.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron-server --all-features --test feedback_require_https_key`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{Vault, VaultConfig};
use oneiron_server::feedback_delivery::{
    FeedbackDeliveryConfig, FeedbackDeliveryError, FeedbackDestination, HttpFeedbackTransport,
};
use serde_json::json;

const KEY: &str = "feedback.delivery.require_https";
/// A plain-HTTP collector on a home network (RFC 1918), never contacted: building a transport
/// sends nothing.
const LAN_HTTP: &str = "http://192.168.1.20/feedback";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open fixture vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        let owner_proof = vault
            .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            _dir: dir,
            vault,
            owner_proof,
        }
    }

    /// The owner turns the HTTPS rule off.
    fn allow_plain_http(&self) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(KEY, json!(false)),
            )
            .expect("the owner sets the key");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change applies at once: {outcome:?}"
        );
    }

    fn transport(&self, endpoint: &str) -> Result<(), FeedbackDeliveryError> {
        HttpFeedbackTransport::for_vault(
            &self.vault,
            FeedbackDeliveryConfig {
                destination: FeedbackDestination::Collector,
                endpoint: endpoint.to_owned(),
            },
            None,
        )
        .map(|_| ())
    }
}

#[test]
fn with_no_row_a_plain_http_endpoint_off_loopback_builds_no_transport() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.transport(LAN_HTTP),
        Err(FeedbackDeliveryError::InvalidEndpoint),
        "the default keeps today's HTTPS rule"
    );
    assert_eq!(
        fixture.transport("http://127.0.0.1:8080/feedback"),
        Ok(()),
        "loopback HTTP passes, as today"
    );
    assert_eq!(
        fixture.transport("https://collector.example/feedback"),
        Ok(())
    );
}

#[test]
fn the_owners_false_lets_a_plain_http_endpoint_build_its_transport() {
    let fixture = Fixture::open();
    fixture.allow_plain_http();
    assert_eq!(
        fixture.transport(LAN_HTTP),
        Ok(()),
        "the owner's false admits plain HTTP off loopback"
    );
}

#[test]
fn the_owners_false_still_refuses_credentials_a_query_and_another_scheme() {
    let fixture = Fixture::open();
    fixture.allow_plain_http();
    for endpoint in [
        "http://user:secret@192.168.1.20/feedback",
        "http://192.168.1.20/feedback?token=1",
        "http://192.168.1.20/feedback#part",
        "ftp://192.168.1.20/feedback",
    ] {
        assert_eq!(
            fixture.transport(endpoint),
            Err(FeedbackDeliveryError::InvalidEndpoint),
            "{endpoint} never passes"
        );
    }
}
