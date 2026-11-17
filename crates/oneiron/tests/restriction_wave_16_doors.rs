//! Restriction wave 16: the two proofs that reach crate-private code through test doors, one
//! module each, in one test target.
//! - `feed_prune`: a cursor the prune passed still gaps after the owner raises the feed
//!   retention, and pages again after its resync.
//! - `space_move`: the owner's space-move undo window (C124).
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test restriction_wave_16_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod feed_prune {
    //! Restriction wave 16, feed prune mark: a cursor the prune passed still gaps after the owner
    //! raises the retention, and pages again after its resync.
    //!
    //! In plain sentences: under the default window a cursor idle 8 days is lapsed, so the prune
    //! deletes the edge rows past it and marks it. When the owner then raises the window to 30 days,
    //! the marked cursor still answers a gap instead of paging past the deleted rows. After the
    //! reader resyncs, reads page again.

    use std::sync::Arc;

    use oneiron::authority::{HostSlipIssuer, MachineRole};
    use oneiron::claim::ScopedReadActorKey;
    use oneiron::consent::AuthenticatedOwner;
    use oneiron::edge::EdgeKind;
    use oneiron::feeds::{
        FEED_RETENTION_SECS, FeedGap, FeedOp, FeedPage, FeedRead, FeedReadRequest, FeedResyncFrom,
        FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest,
    };
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::setting::{
        SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    };
    use oneiron::store::GateDecisionId;
    use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
    use oneiron_keystore::MemoryKeystore;
    use oneiron_store::ports::manual_clock::ManualClock;
    use serde_json::json;

    const T0: u64 = 1_790_000_000;
    const RETENTION_KEY: &str = "feeds.retention.idle_secs";
    const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
    const EIGHT_DAYS: u64 = 8 * 24 * 60 * 60;

    struct Fixture {
        vault: Vault,
        clock: Arc<ManualClock>,
        _dir: tempfile::TempDir,
        issuer: HostSlipIssuer,
        owner: EntityId,
        owner_proof: AuthenticatedOwner,
    }

    impl Fixture {
        /// A rooted vault with its install enrolled and its embedded owner bound, opened owned.
        fn rooted() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let clock = ManualClock::new(T0);
            let keystore = Arc::new(MemoryKeystore::new());
            let mut config = VaultConfig::device();
            config.store_clock = clock.bundle();
            let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
            vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
            vault.prepare_install_signing().expect("install signing");
            let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
            vault.ensure_host_root_slip(&issuer).expect("host root");
            vault
                .provision_engine_machine_identities(&issuer)
                .expect("engine machine identities");
            vault
                .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
                .expect("serving install profile");
            let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
            let owner_proof = vault
                .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
                .expect("owner proof");
            Self {
                vault,
                clock,
                _dir: dir,
                issuer,
                owner,
                owner_proof,
            }
        }

        /// Sets `key` to `value` as the owner. The change applies.
        fn set(&self, key: &str, value: serde_json::Value) {
            let outcome = self
                .vault
                .set_setting(
                    SettingCaller::Owner(&self.owner_proof),
                    SetSetting {
                        key: key.to_owned(),
                        item: None,
                        scope: SettingScope::Vault,
                        mode: SettingMode::Value,
                        value: Some(value),
                        expected_revision: None,
                        why: None,
                        check_in_ref: None,
                    },
                )
                .expect("the owner sets the key");
            assert!(
                matches!(outcome, SetSettingOutcome::Applied { .. }),
                "the owner's change to {key} applies, not {outcome:?}"
            );
        }

        /// The owner's read lane, as a client holds it: a slip the host root mints for the owner,
        /// live for `ttl_secs`.
        fn owner_key_for(&self, slip_id: [u8; 32], ttl_secs: u64) -> ScopedReadActorKey {
            let root = self
                .vault
                .ensure_host_root_slip(&self.issuer)
                .expect("host root slip");
            let issued_at = self.vault.capability_slip_now().expect("authority clock");
            let mut claims = root.claims.clone();
            claims.slip_id = slip_id;
            claims.holder_ref = self.owner.to_hex();
            claims.actor_class = Some("human".into());
            claims.issued_at = issued_at;
            claims.expires_at = issued_at + ttl_secs;
            claims.ttl_secs = ttl_secs;
            let slip = self
                .vault
                .mint_capability_slip(&self.issuer, claims)
                .expect("the owner's slip");
            let challenge = b"restriction-wave-16-prune";
            let proof = self
                .issuer
                .binding_proof(&slip, challenge)
                .expect("binding proof");
            let verified = self
                .vault
                .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
                .expect("verified slip");
            ScopedReadActorKey::from_verified_slip(&verified).expect("owner key")
        }
    }

    fn edges_from(start: FeedStart) -> FeedSubscribeRequest {
        FeedSubscribeRequest {
            selector: FeedSelector {
                sources: vec![FeedSource::Edges],
                kinds: Vec::new(),
                entity_types: Vec::new(),
                predicates: Vec::new(),
            },
            start,
        }
    }

    fn put_person(vault: &Vault) -> EntityId {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("person");
        id
    }

    fn read_page(vault: &Vault, key: &ScopedReadActorKey, subscription: EntityId) -> FeedPage {
        match read_answer(vault, key, subscription) {
            FeedRead::Page(page) => page,
            FeedRead::Gap(gap) => panic!("a page, not {gap:?}"),
        }
    }

    fn read_answer(vault: &Vault, key: &ScopedReadActorKey, subscription: EntityId) -> FeedRead {
        vault
            .feed_read(
                &vault.scoped_read(key.clone()),
                &FeedReadRequest {
                    subscription,
                    limit: None,
                },
            )
            .expect("feed read")
    }

    fn edge_ops(page: &FeedPage, from: EntityId, to: EntityId, kind: &str) -> Vec<FeedOp> {
        page.entries
            .iter()
            .filter(|entry| {
                entry.edge.as_ref().is_some_and(|edge| {
                    edge.source == from && edge.target == to && edge.kind == kind
                })
            })
            .map(|entry| entry.op)
            .collect()
    }

    #[test]
    fn a_cursor_the_prune_passed_still_gaps_after_the_owner_raises_retention() {
        let fx = Fixture::rooted();
        let key = fx.owner_key_for([0x47; 32], 4 * FEED_RETENTION_SECS);
        let lane = fx.vault.scoped_read(key.clone());
        let subscription = fx
            .vault
            .feed_subscribe(&lane, &edges_from(FeedStart::Head))
            .expect("subscribe")
            .subscription;
        let (from, to) = (put_person(&fx.vault), put_person(&fx.vault));
        fx.vault
            .put_edge(&from, EdgeKind::Supports, &to, 0.5)
            .expect("edge");
        // The cursor is never acked: after 8 days idle it is lapsed under the default window.
        fx.clock.set(T0 + EIGHT_DAYS);
        fx.vault
            .put_edge(&from, EdgeKind::Mentions, &to, 0.5)
            .expect("edge past the cursor");
        oneiron::test_doors::feed_prune::prune_feeds(&fx.vault, 10_000).expect("prune");
        fx.set(RETENTION_KEY, json!(THIRTY_DAYS));
        assert_eq!(
            read_answer(&fx.vault, &key, subscription),
            FeedRead::Gap(FeedGap {
                resync_from: FeedResyncFrom::Snapshot,
            }),
            "the marked cursor still gaps under a 30-day retention"
        );
        fx.vault.feed_resync(&lane, subscription).expect("resync");
        let resumed = read_page(&fx.vault, &key, subscription);
        assert!(
            resumed.entries.is_empty(),
            "the resync stands at the head: {resumed:?}"
        );
        assert!(
            fx.vault
                .delete_edge(&from, EdgeKind::Supports, &to)
                .expect("delete"),
            "the supports edge is removed"
        );
        let page = read_page(&fx.vault, &key, subscription);
        assert_eq!(
            edge_ops(&page, from, to, "supports"),
            vec![FeedOp::EdgeRemoved],
            "reads page again after the resync: {page:?}"
        );
    }
}

mod space_move {
    //! The owner's space-move undo window (restriction wave 16, C124).
    //! - With no key set, the incumbent of a swapped-in move retires once the default 30-day
    //!   window passes, and the undo then refuses because the incumbent is retired.
    //! - With the window raised to 60 days, nothing retires past 30 days and the undo stands;
    //!   at 60 days the incumbent retires.

    use std::sync::Arc;

    use oneiron::consent::AuthenticatedOwner;
    use oneiron::embed::{InputKind, SpaceMoveState};
    use oneiron::setting::{
        SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    };
    use oneiron::store::GateDecisionId;
    use oneiron::test_doors::space_move_window::stage_swapped_in_space_move;
    use oneiron::{Vault, VaultConfig};
    use oneiron_store::ports::manual_clock::ManualClock;
    use serde_json::json;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// The vault clock's fixed start: the move swaps in at this second.
    const T0: u64 = 1_790_000_000;

    /// One day, in seconds.
    const DAY_SECS: u64 = 86_400;

    /// The default undo window: 30 days, in seconds.
    const THIRTY_DAYS_SECS: u64 = 30 * DAY_SECS;

    /// The raised undo window: 60 days, in seconds.
    const SIXTY_DAYS_SECS: u64 = 60 * DAY_SECS;

    /// The window key, by name only: it does not exist on the base.
    const UNDO_WINDOW_KEY: &str = "embed.space_move.undo_window_secs";

    /// The staged move's incumbent space.
    const INCUMBENT: &str = "window-test-incumbent@m1@test-rig";

    /// The staged move's candidate space.
    const CANDIDATE: &str = "window-test-candidate@m2@test-rig";

    struct Fixture {
        vault: Vault,
        clock: Arc<ManualClock>,
        owner_proof: AuthenticatedOwner,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        /// A vault on a fixed clock with its embedded owner bound, opened owned: the least a
        /// declare and an owner setting change need.
        fn rooted() -> TestResult<Self> {
            let dir = tempfile::tempdir()?;
            let clock = ManualClock::new(T0);
            let mut config = VaultConfig::device();
            config.embedding_model = None;
            config.dimensions = 4;
            config.store_clock = clock.bundle();
            let vault = Vault::open_owned(dir.path(), config)?;
            let owner = vault.ensure_embedded_owner_actor()?;
            let owner_proof =
                vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
            Ok(Self {
                vault,
                clock,
                owner_proof,
                _dir: dir,
            })
        }

        /// The move swapped in at `T0`: both spaces declared, the text slot bound to the candidate.
        fn swapped_in_at_t0(&self) -> TestResult {
            stage_swapped_in_space_move(&self.vault, INCUMBENT, CANDIDATE, InputKind::Text, T0)?;
            let moves = self.vault.space_moves()?;
            assert_eq!(moves.len(), 1, "the staged move is the only move");
            assert_eq!(
                moves[0].state,
                SpaceMoveState::SwappedIn {
                    at: T0,
                    by_owner: false,
                },
                "the staged move reads swapped in at T0",
            );
            Ok(())
        }

        /// The owner raises the undo window to 60 days.
        fn raise_window_to_60_days(&self) -> TestResult {
            let outcome = self.vault.set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting {
                    key: UNDO_WINDOW_KEY.to_owned(),
                    item: None,
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: Some(json!(SIXTY_DAYS_SECS)),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                },
            )?;
            assert!(
                matches!(outcome, SetSettingOutcome::Applied { .. }),
                "raising the undo window to 60 days applies, got: {outcome:?}",
            );
            Ok(())
        }

        /// Every declared space id.
        fn declared(&self) -> TestResult<Vec<String>> {
            Ok(self
                .vault
                .embedding_spaces()?
                .into_iter()
                .map(|space| space.id)
                .collect())
        }
    }

    #[test]
    fn an_incumbent_retires_once_the_default_30_day_window_passes() -> TestResult {
        let fx = Fixture::rooted()?;
        fx.swapped_in_at_t0()?;

        fx.clock.set(T0 + THIRTY_DAYS_SECS - 1);
        assert_eq!(
            fx.vault.retire_swapped_incumbents()?,
            Vec::<String>::new(),
            "at T0 + 30 days - 1 s nothing retires",
        );
        assert!(
            fx.declared()?.contains(&INCUMBENT.to_owned()),
            "the incumbent is still declared at T0 + 30 days - 1 s",
        );

        fx.clock.set(T0 + THIRTY_DAYS_SECS);
        assert_eq!(
            fx.vault.retire_swapped_incumbents()?,
            vec![INCUMBENT.to_owned()],
            "at T0 + 30 days the incumbent retires",
        );
        assert!(
            !fx.declared()?.contains(&INCUMBENT.to_owned()),
            "the incumbent is retired at T0 + 30 days",
        );
        assert!(
            fx.declared()?.contains(&CANDIDATE.to_owned()),
            "the candidate stays declared at T0 + 30 days",
        );

        match fx.vault.undo_space_move(&fx.owner_proof, CANDIDATE) {
            Ok(()) => panic!("the undo stands after the incumbent retired"),
            Err(err) => assert!(
                format!("{err:?}").contains("retired"),
                "the undo after retirement is refused as retired, got: {err:?}",
            ),
        }
        Ok(())
    }

    #[test]
    fn a_raised_undo_window_keeps_the_incumbent_and_the_undo_past_30_days() -> TestResult {
        // Vault A: past 30 days the incumbent stays and the undo stands.
        let fx = Fixture::rooted()?;
        fx.swapped_in_at_t0()?;
        fx.raise_window_to_60_days()?;

        fx.clock.set(T0 + THIRTY_DAYS_SECS + 1);
        assert_eq!(
            fx.vault.retire_swapped_incumbents()?,
            Vec::<String>::new(),
            "at T0 + 30 days + 1 s with a 60-day window nothing retires",
        );
        assert!(
            fx.declared()?.contains(&INCUMBENT.to_owned()),
            "the incumbent is still declared at T0 + 30 days + 1 s with a 60-day window",
        );
        match fx.vault.undo_space_move(&fx.owner_proof, CANDIDATE) {
            Ok(()) => {}
            Err(err) => {
                panic!("the undo stands at T0 + 30 days + 1 s with a 60-day window, got: {err:?}",)
            }
        }
        assert_eq!(
            fx.vault.kind_slot_bindings()?.text,
            Some(INCUMBENT.to_owned()),
            "the undo binds the text slot back to the incumbent",
        );

        // Vault B: at 60 days the incumbent retires. A second vault carries this half because the
        // undo that stands above consumes the swapped-in move a retirement needs.
        let fx = Fixture::rooted()?;
        fx.swapped_in_at_t0()?;
        fx.raise_window_to_60_days()?;

        fx.clock.set(T0 + SIXTY_DAYS_SECS);
        assert_eq!(
            fx.vault.retire_swapped_incumbents()?,
            vec![INCUMBENT.to_owned()],
            "at T0 + 60 days with a 60-day window the incumbent retires",
        );
        assert!(
            !fx.declared()?.contains(&INCUMBENT.to_owned()),
            "the incumbent is retired at T0 + 60 days with a 60-day window",
        );
        match fx.vault.undo_space_move(&fx.owner_proof, CANDIDATE) {
            Ok(()) => panic!("the undo stands after the incumbent retired at 60 days"),
            Err(err) => assert!(
                format!("{err:?}").contains("retired"),
                "the undo after the 60-day retirement is refused as retired, got: {err:?}",
            ),
        }
        Ok(())
    }
}
