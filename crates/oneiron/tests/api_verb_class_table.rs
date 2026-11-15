//! [L8-57] Per-API verb-class tables (ARCH-0069 #door-reads-action): the
//! door reads what an API call does from its request, REST, GraphQL, MCP and
//! JSON-RPC alike, and classes it from tables shipped as pack data, never as
//! engine policy.
//!
//! - The owner puts a data-only capability pack carrying
//!   `knowledge/verb-classes.json`, and its rows class the calls to its hosts.
//! - A GraphQL call is classed by the root fields it selects, so the client's
//!   operation name and an alias cannot hide a delete.
//! - An unknown host, an unclassed call and a malformed body have no class:
//!   they pass biased-permissive (DEC-0006) when the door resolves them.
//! - A table with two rows on one selector refuses its pack, naming both.
//! - The `local` pack, which a resident agent writes, never carries a table
//!   (RULING L8-57-TABLE-SOURCE = A).
//!
//! On main none of this exists: `read_api_actions`, `ApiVerbClass`,
//! `Vault::api_verb_classes` and the pack file are absent, so this file does
//! not build. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test api_verb_class_table`.

use std::collections::BTreeSet;

use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_record::ApiVerbClass;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{
    LOCAL_PACK_NAME, PackInstallDisposition, PackSource, VERB_CLASS_TABLE_FILE,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ApiAction, ApiProtocol, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor,
    read_api_actions,
};
use reqwest::Url;

use ApiVerbClass::{Destructive, Pay, Read, Send, Write};

/// The table pack the owner puts: an author-scoped name, as a hub pack has.
const PACK: &str = "example.githubclasses";

const PACK_MD: &str = "---
name: example.githubclasses
description: Verb classes for the GitHub API.
version: 1.0.0
kind: capability
---
A data-only pack: one verb-class table, no code.
";

/// The GitHub table of PLAN-L8-57, with a catch-all REST row.
const TABLE: &str = r#"{
  "hosts": ["api.github.com"],
  "rows": [
    {"protocol": "rest", "verb": "GET", "pattern": "/repos/{owner}/{repo}", "class": "read"},
    {"protocol": "rest", "verb": "DELETE", "pattern": "/repos/{owner}/{repo}", "class": "destructive"},
    {"protocol": "rest", "verb": "POST", "pattern": "/repos/{owner}/{repo}/issues", "class": "write"},
    {"protocol": "rest", "verb": "*", "pattern": "/{path*}", "class": "write"},
    {"protocol": "graphql", "verb": "mutation", "pattern": "deleteRepository", "class": "destructive"},
    {"protocol": "graphql", "verb": "mutation", "class": "write"},
    {"protocol": "graphql", "verb": "query", "class": "read"},
    {"protocol": "mcp", "verb": "tools/call", "pattern": "delete_file", "class": "destructive"},
    {"protocol": "json_rpc", "verb": "eth_sendTransaction", "class": "pay"}
  ]
}"#;

struct Fixture {
    vault: Vault,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault opened with the shipped default manifest and its owner's
    /// proof, as an embedded owner holds it.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner_proof,
            _directory: directory,
        }
    }

    /// The owner's put of a table pack `name` carrying `table`.
    fn put_table_pack(&self, name: &str, table: &str) -> oneiron::Result<PackInstallDisposition> {
        let manifest = PACK_MD.replace(PACK, name);
        self.vault.put_pack(
            &self.owner_proof,
            vec![
                HubFile::new("PACK.md", manifest),
                HubFile::new(VERB_CLASS_TABLE_FILE, table),
            ],
        )
    }

    /// The owner's put of the GitHub table pack, which lands Active.
    fn put_github_table(&self) {
        match self.put_table_pack(PACK, TABLE) {
            Ok(PackInstallDisposition::Installed(receipt)) => assert_eq!(receipt.pack_name, PACK),
            other => panic!("the owner's put installs the data-only table pack: {other:?}"),
        }
    }

    /// Each action of the call, beside the classes the installed tables
    /// give it.
    fn classes(
        &self,
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> Vec<(ApiAction, BTreeSet<ApiVerbClass>)> {
        let url = Url::parse(url).expect("a URL");
        let actions = read_api_actions(&url, method, body.map(str::as_bytes));
        let classes = self
            .vault
            .api_verb_classes(&actions)
            .expect("read the classes");
        assert_eq!(classes.len(), actions.len(), "one class set per action");
        actions.into_iter().zip(classes).collect()
    }

    /// The classes of the call's one action of `protocol`.
    fn classes_of(
        &self,
        protocol: ApiProtocol,
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> BTreeSet<ApiVerbClass> {
        let read = self.classes(method, url, body);
        let mut of = read
            .iter()
            .filter(|(action, _)| action.protocol == protocol);
        let (_, classes) = of
            .next()
            .unwrap_or_else(|| panic!("a {protocol:?} action: {read:?}"));
        assert!(of.next().is_none(), "one {protocol:?} action: {read:?}");
        classes.clone()
    }
}

fn set<const N: usize>(classes: [ApiVerbClass; N]) -> BTreeSet<ApiVerbClass> {
    BTreeSet::from(classes)
}

#[test]
fn rest_rows_class_a_get_as_read_and_a_delete_as_destructive() {
    let f = Fixture::new();
    let repo = "https://api.github.com/repos/o/r";
    assert_eq!(
        f.classes_of(ApiProtocol::Rest, "GET", repo, None),
        set([]),
        "before the put, no table classes the call"
    );
    f.put_github_table();

    let read = f.classes("GET", repo, None);
    assert_eq!(read.len(), 1, "a bodiless GET is one REST action: {read:?}");
    let (action, classes) = &read[0];
    assert_eq!(
        (
            action.host.as_str(),
            action.verb.as_str(),
            action.target.as_str()
        ),
        ("api.github.com", "GET", "/repos/o/r")
    );
    assert_eq!(*classes, set([Read]));
    assert_eq!(
        f.classes_of(ApiProtocol::Rest, "delete", repo, None),
        set([Destructive])
    );
    // The same path, written another way, reads as the same row.
    for written in [
        "https://API.github.com/repos/o/r/",
        "https://api.github.com//repos/o/r",
        "https://api.github.com/%72epos/o/r?per_page=1",
        "https://api.github.com/REPOS/o/r",
    ] {
        assert_eq!(
            f.classes_of(ApiProtocol::Rest, "DELETE", written, None),
            set([Destructive]),
            "{written}"
        );
    }
    // More literal segments win; the catch-all classes the rest.
    assert_eq!(
        f.classes_of(
            ApiProtocol::Rest,
            "POST",
            "https://api.github.com/repos/o/r/issues",
            None
        ),
        set([Write])
    );
    assert_eq!(
        f.classes_of(
            ApiProtocol::Rest,
            "PUT",
            "https://api.github.com/user/starred/o/r",
            None
        ),
        set([Write])
    );
    // The catch-all's tail needs one segment or more: the root is unclassed.
    assert_eq!(
        f.classes_of(ApiProtocol::Rest, "GET", "https://api.github.com/", None),
        set([])
    );
}

#[test]
fn a_graphql_mutation_is_read_by_its_root_fields_not_its_name() {
    let f = Fixture::new();
    f.put_github_table();
    let graphql = "https://api.github.com/graphql";
    let body = |query: &str| serde_json::json!({ "query": query }).to_string();

    let delete = body(
        "mutation deleteRepository { deleteRepository(input: {repositoryId: \"R\"}) { clientMutationId } }",
    );
    let read = f.classes("POST", graphql, Some(&delete));
    let graph: Vec<_> = read
        .iter()
        .filter(|(action, _)| action.protocol == ApiProtocol::GraphQl)
        .map(|(action, classes)| {
            (
                action.verb.as_str(),
                action.target.as_str(),
                classes.clone(),
            )
        })
        .collect();
    assert_eq!(
        graph,
        vec![("mutation", "deleteRepository", set([Destructive]))]
    );
    // The REST action of the same POST stands beside it: the catch-all row.
    assert_eq!(
        f.classes_of(ApiProtocol::Rest, "POST", graphql, Some(&delete)),
        set([Write])
    );

    // The client picks the operation's name and the field's alias: neither hides the delete.
    let renamed = body(
        "# a comment { not a field }\nmutation harmless($id: ID! = \"x\") @live { kept: deleteRepository(input: {repositoryId: $id, note: \"}\"}) { clientMutationId } }",
    );
    assert_eq!(
        f.classes_of(ApiProtocol::GraphQl, "POST", graphql, Some(&renamed)),
        set([Destructive])
    );
    // A root fragment spread reads as the fragment's own root fields.
    let spread = body(
        "mutation M { ...Gone } fragment Gone on Mutation { ... on Mutation { deleteRepository(input: {}) { clientMutationId } } }",
    );
    assert_eq!(
        f.classes_of(ApiProtocol::GraphQl, "POST", graphql, Some(&spread)),
        set([Destructive])
    );
    // Another mutation field falls to the type's `*` row.
    let star = body("mutation { addStar(input: {starrableId: \"R\"}) { clientMutationId } }");
    assert_eq!(
        f.classes_of(ApiProtocol::GraphQl, "POST", graphql, Some(&star)),
        set([Write])
    );
    // The `{ .. }` shorthand is a query.
    let viewer = body("{ viewer { login } }");
    let read = f.classes("POST", graphql, Some(&viewer));
    assert!(
        read.iter()
            .any(|(action, classes)| action.protocol == ApiProtocol::GraphQl
                && action.verb == "query"
                && action.target == "viewer"
                && *classes == set([Read])),
        "{read:?}"
    );
    // A document of two operations runs the one `operationName` names.
    let both = serde_json::json!({
        "query": "query Who { viewer { login } } mutation Gone { deleteRepository(input: {}) { clientMutationId } }",
        "operationName": "Who",
    })
    .to_string();
    assert_eq!(
        f.classes_of(ApiProtocol::GraphQl, "POST", graphql, Some(&both)),
        set([Read])
    );
}

#[test]
fn an_mcp_tools_call_and_a_json_rpc_method_are_read_from_the_body() {
    let f = Fixture::new();
    f.put_github_table();
    let endpoint = "https://api.github.com/mcp";

    let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"a"}}}"#;
    let read = f.classes("POST", endpoint, Some(call));
    let (action, classes) = read
        .iter()
        .find(|(action, _)| action.protocol == ApiProtocol::Mcp)
        .expect("an MCP action");
    assert_eq!(
        (action.verb.as_str(), action.target.as_str()),
        ("tools/call", "delete_file")
    );
    assert_eq!(*classes, set([Destructive]));

    let send = r#"{"jsonrpc":"2.0","id":2,"method":"eth_sendTransaction","params":[{"to":"0x0"}]}"#;
    assert_eq!(
        f.classes_of(ApiProtocol::JsonRpc, "POST", endpoint, Some(send)),
        set([Pay])
    );

    // A batch of two reads as two actions beside the REST one.
    let batch = format!("[{call},{send}]");
    let read = f.classes("POST", endpoint, Some(&batch));
    let protocols: Vec<_> = read.iter().map(|(action, _)| action.protocol).collect();
    assert_eq!(
        protocols,
        vec![ApiProtocol::Rest, ApiProtocol::Mcp, ApiProtocol::JsonRpc]
    );
    // A tool the table does not name has no class.
    let other = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file"}}"#;
    assert_eq!(
        f.classes_of(ApiProtocol::Mcp, "POST", endpoint, Some(other)),
        set([])
    );
}

#[test]
fn an_unknown_host_or_shape_has_no_class() {
    let f = Fixture::new();
    f.put_github_table();
    assert_eq!(
        f.classes("GET", "https://example.com/x", None),
        vec![(
            ApiAction {
                host: "example.com".to_owned(),
                protocol: ApiProtocol::Rest,
                verb: "GET".to_owned(),
                target: "/x".to_owned(),
            },
            set([])
        )]
    );
    // A port is part of the host: the table names api.github.com alone.
    assert_eq!(
        f.classes_of(
            ApiProtocol::Rest,
            "GET",
            "https://api.github.com:8443/repos/o/r",
            None
        ),
        set([])
    );
    // Malformed GraphQL, broken JSON and a non-RPC object add no action:
    // only the REST action stands.
    for body in [
        r#"{"query":"mutation { deleteRepository(input: {}) { clientMutationId }"}"#,
        r#"{"query":"mutation { deleteRepository"#,
        r#"{"jsonrpc":"1.0","method":"eth_sendTransaction"}"#,
        "not json",
    ] {
        let read = f.classes("POST", "https://api.github.com/graphql", Some(body));
        assert_eq!(read.len(), 1, "{body}: {read:?}");
        assert_eq!(read[0].0.protocol, ApiProtocol::Rest, "{body}");
    }
}

#[test]
fn a_table_with_conflicting_rows_refuses_its_pack() {
    let f = Fixture::new();
    let conflicting = r#"{"hosts":["api.example.org"],"rows":[
        {"protocol":"rest","verb":"GET","pattern":"/a","class":"read"},
        {"protocol":"rest","verb":"get","pattern":"/A/","class":"write"}
    ]}"#;
    let error = f
        .put_table_pack("example.conflicting", conflicting)
        .expect_err("two rows on one selector refuse the pack");
    let message = error.to_string();
    assert!(
        message.contains("row 1 (rest GET /a -> read)")
            && message.contains("row 2 (rest get /A/ -> write)"),
        "names both rows: {message}"
    );
    assert!(
        f.vault
            .installed_pack("example.conflicting")
            .expect("read the catalog")
            .is_none(),
        "the pack is not installed"
    );
    // A row that does not check refuses the pack too.
    for broken in [
        r#"{"hosts":["api.example.org"],"rows":[{"protocol":"rest","verb":"GET","pattern":"a/{x}","class":"read"}]}"#,
        r#"{"hosts":["api.example.org"],"rows":[{"protocol":"rest","verb":"GET","pattern":"/{rest*}/a","class":"read"}]}"#,
        r#"{"hosts":["api.example.org"],"rows":[{"protocol":"graphql","verb":"fragment","class":"read"}]}"#,
        r#"{"hosts":["api.example.org"],"rows":[{"protocol":"rest","verb":"GET","class":"harmless"}]}"#,
        r#"{"hosts":[],"rows":[{"protocol":"rest","verb":"GET","class":"read"}]}"#,
    ] {
        assert!(
            f.put_table_pack("example.broken", broken).is_err(),
            "{broken}"
        );
    }
}

#[test]
fn an_agent_written_local_pack_cannot_carry_a_table() {
    let f = Fixture::new();
    let lying = r#"{"hosts":["api.github.com"],"rows":[
        {"protocol":"rest","verb":"DELETE","pattern":"/repos/{owner}/{repo}","class":"read"}
    ]}"#;
    let local_md = format!(
        "---\nname: {LOCAL_PACK_NAME}\ndescription: This vault's own hooks.\nversion: 2\nkind: capability\n---\n"
    );
    let files = || {
        vec![
            HubFile::new("PACK.md", local_md.as_str()),
            HubFile::new(VERB_CLASS_TABLE_FILE, lying),
        ]
    };
    let agent = WriteActor::new(
        EntityId::from_bytes([0x5c; 16]).expect("an id"),
        EdgeActorClass::Agent,
    );
    let error = f
        .vault
        .put_local_pack_as_agent(&agent, files())
        .expect_err("an agent's local pack carries no table");
    assert!(
        error
            .to_string()
            .contains("the local pack carries no verb-class table"),
        "{error}"
    );
    // The source itself is refused, whoever puts it.
    assert!(PackSource::from_files(files()).is_err());
    assert!(f.vault.put_pack(&f.owner_proof, files()).is_err());
    assert_eq!(
        f.classes_of(
            ApiProtocol::Rest,
            "DELETE",
            "https://api.github.com/repos/o/r",
            None
        ),
        set([]),
        "no table classes the call"
    );
}

#[test]
fn two_packs_that_class_one_call_give_it_both_classes() {
    let f = Fixture::new();
    f.put_github_table();
    let issues = r#"{"hosts":["api.github.com"],"rows":[
        {"protocol":"rest","verb":"POST","pattern":"/repos/{owner}/{repo}/issues","class":"send"}
    ]}"#;
    match f.put_table_pack("example.issuesend", issues) {
        Ok(PackInstallDisposition::Installed(_)) => {}
        other => panic!("the second table pack installs: {other:?}"),
    }
    let url = "https://api.github.com/repos/o/r/issues";
    assert_eq!(
        f.classes_of(ApiProtocol::Rest, "POST", url, None),
        set([Write, Send])
    );

    // The table is read live: removing a pack drops its rows at once.
    f.vault
        .remove_pack(&f.owner_proof, "example.issuesend")
        .expect("the owner removes the pack");
    assert_eq!(
        f.classes_of(ApiProtocol::Rest, "POST", url, None),
        set([Write])
    );
    f.vault
        .remove_pack(&f.owner_proof, PACK)
        .expect("the owner removes the pack");
    assert_eq!(f.classes_of(ApiProtocol::Rest, "POST", url, None), set([]));
}
