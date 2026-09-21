use super::*;

#[test]
fn no_subcommand_defaults_to_serve() {
    let cli = Cli::try_parse_from(["oneiron-server", "--port", "9191"]).unwrap();
    match cli.into_command() {
        Command::Serve(args) => assert_eq!(args.port, Some(9191)),
        _ => panic!("expected serve command"),
    }
}

#[test]
fn explicit_serve_accepts_current_flags() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "serve",
        "--vault-path",
        "/tmp/oneiron-vault",
        "--host",
        "127.0.0.1",
        "--port",
        "9191",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Serve(args) => {
            assert_eq!(args.vault_path, Some(PathBuf::from("/tmp/oneiron-vault")));
            assert_eq!(args.host.as_deref(), Some("127.0.0.1"));
            assert_eq!(args.port, Some(9191));
        }
        _ => panic!("expected serve command"),
    }
}

/// The managed argv group has to survive the parser as one coherent set,
/// on the explicit `serve` form as well as the bare one — the supervisor
/// spawns `oneiron-server serve ...`, and every field it passes must reach
/// `ServeArgs` for the managed-mode validator to act on.
#[test]
fn explicit_serve_accepts_the_managed_argv_group() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "serve",
        "--managed-by-hypnos",
        "--contract-version",
        "1",
        "--vault-name",
        "canary-vault",
        "--data-dir",
        "/run/oneiron/canary",
        "--http-socket",
        "/run/oneiron/canary/http.sock",
        "--ctl-socket",
        "/run/oneiron/canary/ctl.sock",
        "--hypnos-socket",
        "/run/hypnos/sup.sock",
        "--ready-fd",
        "7",
        "--credentials-fd",
        "9",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Serve(args) => {
            assert!(args.managed_by_hypnos);
            assert_eq!(args.contract_version, Some(1));
            assert_eq!(args.vault_name.as_deref(), Some("canary-vault"));
            assert_eq!(args.data_dir, Some(PathBuf::from("/run/oneiron/canary")));
            assert_eq!(
                args.http_socket,
                Some(PathBuf::from("/run/oneiron/canary/http.sock"))
            );
            assert_eq!(
                args.ctl_socket,
                Some(PathBuf::from("/run/oneiron/canary/ctl.sock"))
            );
            assert_eq!(
                args.hypnos_socket,
                Some(PathBuf::from("/run/hypnos/sup.sock"))
            );
            assert_eq!(args.ready_fd, Some(7));
            assert_eq!(args.credentials_fd, Some(9));
        }
        _ => panic!("expected serve command"),
    }
}

/// Off by default: the switch is the ONLY thing that selects managed mode,
/// so today's argv must still land on an unmanaged serve.
#[test]
fn serve_is_unmanaged_without_the_switch() {
    let cli = Cli::try_parse_from(["oneiron-server", "serve", "--port", "9191"]).unwrap();
    match cli.into_command() {
        Command::Serve(args) => {
            assert!(!args.managed_by_hypnos);
            assert!(args.contract_version.is_none());
            assert!(args.credentials_fd.is_none());
        }
        _ => panic!("expected serve command"),
    }
}

#[test]
fn explicit_serve_accepts_cors_origins_alias() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "serve",
        "--cors-origins",
        "https://a.example,https://b.example",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Serve(args) => assert_eq!(
            args.allowed_origins,
            Some(vec![
                "https://a.example".to_owned(),
                "https://b.example".to_owned()
            ])
        ),
        _ => panic!("expected serve command"),
    }
}

#[test]
fn revoke_accepts_client_and_serve_config_flags() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "revoke",
        "--client",
        "0123456789abcdef",
        "--vault-path",
        "/tmp/oneiron-vault",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Revoke(args) => {
            assert_eq!(args.client, "0123456789abcdef");
            assert_eq!(
                args.serve.vault_path,
                Some(PathBuf::from("/tmp/oneiron-vault"))
            );
        }
        _ => panic!("expected revoke command"),
    }
}

#[test]
fn skills_pack_defaults_to_markdown_output() {
    let cli = Cli::try_parse_from(["oneiron-server", "skills-pack"]).unwrap();

    match cli.into_command() {
        Command::SkillsPack(args) => {
            assert!(!args.json);
            assert!(!args.path);
        }
        _ => panic!("expected skills-pack command"),
    }
}

#[test]
fn skills_pack_accepts_json_output() {
    let cli = Cli::try_parse_from(["oneiron-server", "skills-pack", "--json"]).unwrap();

    match cli.into_command() {
        Command::SkillsPack(args) => {
            assert!(args.json);
            assert!(!args.path);
        }
        _ => panic!("expected skills-pack command"),
    }
}

#[test]
fn skills_pack_path_conflicts_with_json() {
    let err = match Cli::try_parse_from(["oneiron-server", "skills-pack", "--json", "--path"]) {
        Ok(_) => panic!("expected --json and --path to conflict"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn provenance_accepts_sha_and_vault_path() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "provenance",
        "0123456789abcdef0123456789abcdef01234567",
        "--vault-path",
        "/tmp/oneiron-vault",
        "--repo-path",
        "/tmp/repo",
        "--git-notes",
        "--include-payload",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Provenance(args) => {
            assert_eq!(
                args.sha.as_deref(),
                Some("0123456789abcdef0123456789abcdef01234567")
            );
            assert_eq!(args.vault_path, PathBuf::from("/tmp/oneiron-vault"));
            assert_eq!(args.repo_path, PathBuf::from("/tmp/repo"));
            assert!(args.git_notes);
            assert!(args.include_payload);
        }
        _ => panic!("expected provenance command"),
    }
}

#[test]
fn provenance_accepts_claim_id_lookup() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "provenance",
        "--claim-id",
        "0123456789abcdef0123456789abcdef",
        "--vault-path",
        "/tmp/oneiron-vault",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Provenance(args) => {
            assert_eq!(
                args.claim_id.as_deref(),
                Some("0123456789abcdef0123456789abcdef")
            );
            assert!(args.sha.is_none());
        }
        _ => panic!("expected provenance command"),
    }
}

#[test]
fn provenance_requires_sha_or_claim_id() {
    let err = match Cli::try_parse_from([
        "oneiron-server",
        "provenance",
        "--vault-path",
        "/tmp/oneiron-vault",
    ]) {
        Ok(_) => panic!("expected provenance target requirement"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn token_mint_parses_scope_list_and_principal_ref() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "token",
        "mint",
        "--scope",
        "core:read,companion:profile:read",
        "--principal-ref",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Token(TokenCommand::Mint(args)) => {
            assert_eq!(
                args.scope,
                Some(vec![
                    "core:read".to_owned(),
                    "companion:profile:read".to_owned()
                ])
            );
            assert_eq!(
                args.principal_ref.as_deref(),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            );
        }
        _ => panic!("expected token mint command"),
    }
}

#[test]
fn token_mint_defaults_to_owner_grade_claims() {
    let cli = Cli::try_parse_from(["oneiron-server", "token", "mint"]).unwrap();

    match cli.into_command() {
        Command::Token(TokenCommand::Mint(args)) => {
            assert!(args.scope.is_none());
            assert!(args.principal_ref.is_none());
        }
        _ => panic!("expected token mint command"),
    }
}

#[test]
fn token_revoke_parses_jti_and_serve_config_flags() {
    let cli = Cli::try_parse_from([
        "oneiron-server",
        "token",
        "revoke",
        "--jti",
        "0123456789abcdef0123456789abcdef",
        "--vault-path",
        "/tmp/oneiron-vault",
    ])
    .unwrap();

    match cli.into_command() {
        Command::Token(TokenCommand::Revoke(args)) => {
            assert_eq!(args.jti, "0123456789abcdef0123456789abcdef");
            assert_eq!(
                args.serve.vault_path,
                Some(PathBuf::from("/tmp/oneiron-vault"))
            );
        }
        _ => panic!("expected token revoke command"),
    }
}

/// Revocation names an identity; there is no "revoke everything" arm here,
/// because that lever is rotation.
#[test]
fn token_revoke_requires_a_jti() {
    let err = match Cli::try_parse_from(["oneiron-server", "token", "revoke"]) {
        Ok(_) => panic!("expected --jti to be required"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

/// Every short `api` command parses to its own typed variant. The rows are
/// per command because the family's whole point is that four shaped calls
/// plus one escape hatch cover the ladder; a variant that silently parsed
/// as another would send the wrong request to a real vault.
#[test]
fn api_subcommands_parse_to_their_typed_variants() {
    let rows: Vec<(Vec<&str>, ApiCommand)> = vec![
        (vec!["api", "discover"], ApiCommand::Discover),
        (
            vec!["api", "search", "kickoff notes"],
            ApiCommand::Search {
                query: "kickoff notes".to_owned(),
                limit: None,
            },
        ),
        (
            vec!["api", "search", "kickoff notes", "--limit", "5"],
            ApiCommand::Search {
                query: "kickoff notes".to_owned(),
                limit: Some(5),
            },
        ),
        (
            vec!["api", "get", "entity-42"],
            ApiCommand::Get {
                entity_id: "entity-42".to_owned(),
            },
        ),
        (
            vec!["api", "call", "board.append", "--data", "@request.json"],
            ApiCommand::Call {
                verb: "board.append".to_owned(),
                data: "@request.json".to_owned(),
            },
        ),
        (
            vec!["api", "raw", "GET", "/api/health"],
            ApiCommand::Raw {
                method: "GET".to_owned(),
                path: "/api/health".to_owned(),
                data: None,
                content_type: None,
            },
        ),
        (
            vec!["api", "raw", "POST", "/api/lease/revoke", "--data", "-"],
            ApiCommand::Raw {
                method: "POST".to_owned(),
                path: "/api/lease/revoke".to_owned(),
                data: Some("-".to_owned()),
                content_type: None,
            },
        ),
        // The media type is OPTIONAL and additive: omitting it leaves the
        // JSON default in force, naming it carries a wire protocol the
        // shaped commands have no room for.
        (
            vec![
                "api",
                "raw",
                "POST",
                "/git/info/refs",
                "--data",
                "-",
                "--content-type",
                "application/x-git-upload-pack-request",
            ],
            ApiCommand::Raw {
                method: "POST".to_owned(),
                path: "/git/info/refs".to_owned(),
                data: Some("-".to_owned()),
                content_type: Some("application/x-git-upload-pack-request".to_owned()),
            },
        ),
    ];

    for (argv, expected) in rows {
        let cli = Cli::try_parse_from(std::iter::once("oneiron").chain(argv.iter().copied()))
            .unwrap_or_else(|error| panic!("{argv:?} must parse: {error}"));

        match cli.into_command() {
            Command::Api(args) => assert_eq!(args.command, expected, "{argv:?}"),
            _ => panic!("expected api command for {argv:?}"),
        }
    }
}

/// The base URL defaults to a localhost server and the credential is named
/// by ENVIRONMENT VARIABLE, never taken as a value on the command line.
#[test]
fn api_defaults_to_localhost_and_an_env_named_secret() {
    let cli = Cli::try_parse_from(["oneiron", "api", "discover"]).unwrap();

    match cli.into_command() {
        Command::Api(args) => {
            assert_eq!(args.base_url, "http://127.0.0.1:3000");
            assert_eq!(args.secret_env, "ONEIRON_SECRET");
        }
        _ => panic!("expected api command"),
    }
}

/// `api` is a family, not a call: bare `oneiron api` must not fall through
/// to the default `serve` arm and start a daemon.
#[test]
fn api_without_a_subcommand_is_a_parse_error() {
    let err = match Cli::try_parse_from(["oneiron", "api"]) {
        Ok(_) => panic!("expected `api` to require a subcommand"),
        Err(err) => err,
    };

    // Clap shows help when a required subcommand has no arguments. This
    // must still be a failing parse, not a successful `--help` exit.
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
        "bare `api` must not resolve to another command"
    );
    assert!(err.use_stderr());
    assert_eq!(err.exit_code(), 2);
}

/// Mirrors the server-side grammar rule: an owner-grade token is never
/// bound to a third-party principal, so the flag pair is rejected at parse.
#[test]
fn token_mint_principal_ref_requires_scope() {
    let err = match Cli::try_parse_from([
        "oneiron-server",
        "token",
        "mint",
        "--principal-ref",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]) {
        Ok(_) => panic!("expected --principal-ref to require --scope"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}
