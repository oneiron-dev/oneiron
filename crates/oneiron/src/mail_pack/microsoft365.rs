//! The Microsoft 365 wire of the mail importer (FIX 12559 row 3;
//! MAIL-PROVIDERS = A): Microsoft Graph mail over `reqwest::blocking`, for a
//! Microsoft 365 mailbox source.
//!
//! Each provider call reads the source's own credential at its door
//! ([`Vault::with_source_token_at_door`]), effector
//! `connector:microsoft365`. HTTPS to Graph only, no redirects; a link Graph
//! answers with is followed only on Graph's own origin. Inside each door,
//! before the credential presented there reads anything, the wire checks
//! once per credential that its user is the mailbox the source names.
//! Message ids are Graph's immutable ids, so a move keeps a message's id.
//!
//! A folder counts by the nearest well-known folder it is, or sits under:
//! mail anywhere under Deleted Items, Junk Email, Drafts, Outbox or
//! Conversation History is not copied, and mail moved anywhere under Deleted
//! Items or Junk Email is deleted at the provider. A folder the wire cannot
//! place under the mailbox's root, after reading the folders again once for
//! it, is refused rather than counted as copied.
//!
//! Graph tracks changes per mail folder, so the source's change anchor is a
//! delta link per folder, as the folders stood when they were read. A
//! folder's first round lists all its mail, page by page across steps, and
//! the mail its pages name that the copy setting keeps (received since its
//! cutoff, or all) is filed, so mail that reaches a copied folder by any
//! path (a move, a copy, an import) is filed whatever its age; a message
//! copied already lands as the same. The newest-first copy waits while a
//! round is mid-way, so nothing it copies sits in a folder whose round has
//! not begun. A folder not copied is read only for the mail that leaves it.
//! A message a folder reports removed is looked up: gone, or under Deleted
//! Items or Junk Email, it is deleted at the provider; anywhere else it only
//! moved, and one that left a folder not copied for a copied one is filed
//! into the mailbox. A copied folder that is gone, or that moved under a
//! folder not copied, has each copied message under it looked up again; a
//! folder that moved out from under one lists all its mail in its next
//! round. When a round ends, the folders made since the anchor's folders
//! were read join it, listing all their mail.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::credential::WireReads;
use super::rest::{
    self, RestAnswer, VerifiedCredentials, array, bearer_header, header_value, html_text, refused,
    text_of, tidy_text,
};
use super::source::MailProvider;
use super::wire::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProviderWire, MailSyncSource,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The custody effector a Microsoft 365 mail credential is bound to.
pub const MICROSOFT365_CONNECTOR_EFFECTOR: &str = "connector:microsoft365";

const GRAPH_ORIGIN: &str = "https://graph.microsoft.com/";
pub(super) const GRAPH_ME_URL: &str = "https://graph.microsoft.com/v1.0/me";
const GRAPH_PAGE_SIZE: u32 = 100;
const PREFER_IMMUTABLE_IDS: &str = "IdType=\"ImmutableId\"";
const PREFER_TEXT_BODY: &str = "IdType=\"ImmutableId\", outlook.body-content-type=\"text\"";
/// A change-feed page: immutable ids, up to 100 entries.
const PREFER_DELTA: &str = "IdType=\"ImmutableId\", odata.maxpagesize=100";
/// The most attachment pages one message's list is read to; a list longer
/// than that keeps its first pages' descriptions.
const MAX_ATTACHMENT_PAGES: usize = 50;
/// The well-known folders the wire names.
const WELL_KNOWN_FOLDERS: [&str; 9] = [
    "msgfolderroot",
    "inbox",
    "sentitems",
    "archive",
    "deleteditems",
    "junkemail",
    "drafts",
    "outbox",
    "conversationhistory",
];
/// The well-known folders whose mail is not copied: deleted mail and junk,
/// and what is not mail yet.
const SKIPPED_FOLDERS: [&str; 5] = [
    "deleteditems",
    "junkemail",
    "drafts",
    "outbox",
    "conversationhistory",
];
/// The folders a message moved into counts as deleted from.
const TRASH_FOLDERS: [&str; 2] = ["deleteditems", "junkemail"];
/// The most folders one source's anchor tracks.
const MAX_FOLDERS: usize = 1_000;
/// The most folder reads one change-feed page makes while folders are quiet.
const MAX_FOLDER_READS_PER_PAGE: usize = 100;
/// The longest Graph id read.
const MAX_GRAPH_ID_BYTES: usize = 512;
/// What a header stage selects.
const MESSAGE_FIELDS: &str = "id,conversationId,internetMessageId,subject,from,toRecipients,ccRecipients,replyTo,receivedDateTime,sentDateTime,parentFolderId,isDraft,categories,internetMessageHeaders";

/// A source's change anchor: one delta link per folder.
#[derive(Debug, Default, Serialize, Deserialize)]
struct GraphAnchor {
    folders: BTreeMap<String, String>,
    /// The folders whose mail was not copied when the folders were read.
    #[serde(default)]
    skipped: BTreeSet<String>,
}

/// Where a change-feed read stands between its pages.
#[derive(Debug, Default, Serialize, Deserialize)]
struct GraphHistoryCursor {
    /// The folder being read, by its place in the anchor.
    folder: usize,
    /// The next link within that folder's round, when it has one.
    link: Option<String>,
    /// The delta links of the folders read to the end so far.
    reached: BTreeMap<String, String>,
    /// The folders not copied when the anchor was taken that were met copied
    /// during this round, so their copies are looked up again should they
    /// end it not copied.
    #[serde(default)]
    met_copied: BTreeSet<String>,
}

/// One mailbox's folders: the well-known ones by name (the root among
/// them), and each folder's parent, so a folder counts by the well-known
/// folder it sits under.
#[derive(Debug, Clone, Default)]
struct FolderTree {
    names: BTreeMap<String, &'static str>,
    parents: BTreeMap<String, String>,
}

impl FolderTree {
    /// The well-known folder `id` is, or the nearest it sits under.
    ///
    /// # Errors
    ///
    /// A folder that does not reach a well-known one through folders read,
    /// or whose parents loop.
    fn class(&self, id: &str) -> Result<&'static str> {
        let mut at = id;
        // A walk longer than the folders read has met a loop.
        for _ in 0..=self.parents.len() {
            if let Some(name) = self.names.get(at) {
                return Ok(*name);
            }
            at = self
                .parents
                .get(at)
                .ok_or_else(|| refused("graph_mail_folder_unresolved"))?;
        }
        Err(refused("graph_mail_folder_parents_loop"))
    }

    fn knows(&self, id: &str) -> bool {
        self.names.contains_key(id) || self.parents.contains_key(id)
    }

    /// Whether mail in the folder `id` is not copied.
    fn skipped(&self, id: &str) -> Result<bool> {
        Ok(SKIPPED_FOLDERS.contains(&self.class(id)?))
    }

    /// Whether mail moved into the folder `id` is deleted at the provider.
    fn trash(&self, id: &str) -> Result<bool> {
        Ok(TRASH_FOLDERS.contains(&self.class(id)?))
    }

    /// The label mail in the folder `id` holds.
    fn label(&self, id: &str) -> String {
        self.names
            .get(id)
            .map_or_else(|| folder_label(id), |name| (*name).to_owned())
    }
}

/// Host-side Microsoft Graph mail wire over `reqwest::blocking`, for the
/// Microsoft 365 mailbox sources of one vault.
pub struct HttpGraphMailWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The credentials this wire has seen read their source's mailbox.
    verified: VerifiedCredentials,
    /// Each source's folders, read once and again when a folder is met
    /// that the read did not hold.
    folders: RefCell<BTreeMap<EntityId, FolderTree>>,
    /// The folders, by source, met unknown and read again for this wire's
    /// life.
    reread: RefCell<BTreeSet<(EntityId, String)>>,
}

impl<'v> HttpGraphMailWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        Ok(Self {
            vault,
            client: rest::https_client()?,
            verified: VerifiedCredentials::new(),
            folders: RefCell::new(BTreeMap::new()),
            reread: RefCell::new(BTreeSet::new()),
        })
    }

    /// One GET on Graph with the source's credential, read at its door.
    fn get(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
        prefer: &str,
    ) -> Result<RestAnswer> {
        if source.provider != MailProvider::Microsoft365 {
            return Err(refused("graph_mail_wire_reads_microsoft365_mailboxes_only"));
        }
        if !url.starts_with(GRAPH_ORIGIN) {
            return Err(refused("graph_mail_link_not_on_graph"));
        }
        let mut answer: Option<RestAnswer> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Mailbox,
            MICROSOFT365_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = bearer_header(token)?;
                // The credential presented here is the one checked.
                if !self.verified.holds(source.source_ref, token) {
                    let request = self
                        .client
                        .get(GRAPH_ME_URL)
                        .query(&[("$select", "mail,userPrincipalName")])
                        .header(AUTHORIZATION, auth.clone())
                        .header("Prefer", PREFER_IMMUTABLE_IDS);
                    let me = rest::send(request)?
                        .found_or_gone("graph_mail")?
                        .ok_or_else(|| refused("graph_mail_user_not_found"))?;
                    reads_mailbox(&me, source)?;
                    self.verified.insert(source.source_ref, token);
                }
                let request = self
                    .client
                    .get(url)
                    .query(query)
                    .header(AUTHORIZATION, auth)
                    .header("Prefer", prefer);
                answer = Some(rest::send(request)?);
                Ok(())
            },
        )?;
        answer.ok_or_else(|| refused("graph_mail_credential_door_refused"))
    }

    /// [`Self::get`]'s JSON; `None` for Graph's "not found".
    fn found(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
        prefer: &str,
    ) -> Result<Option<Value>> {
        self.get(source, url, query, prefer)?
            .found_or_gone("graph_mail")
    }

    /// One page of messages `url` lists (a listing or a search, or the
    /// next page Graph linked to), drafts and the mail of folders not copied
    /// left out.
    fn listed_messages(
        &self,
        source: &MailSyncSource,
        url: &str,
        params: &[(&str, String)],
    ) -> Result<MailIdPage> {
        let listed = self
            .found(source, url, params, PREFER_IMMUTABLE_IDS)?
            .ok_or_else(|| refused("graph_mail_listing_not_found"))?;
        let mut messages = Vec::new();
        let mut tree = self.tree(source)?;
        for message in array(&listed, "value") {
            let folder = text_of(message.get("parentFolderId")).unwrap_or_default();
            let draft = message
                .get("isDraft")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !tree.knows(&folder) {
                tree = self.tree_knowing(source, &folder)?;
            }
            if draft || tree.skipped(&folder)? {
                continue;
            }
            messages.push(MailMessageRef {
                provider_id: graph_id(message.get("id"))?,
                thread_id: text_of(message.get("conversationId")),
            });
        }
        Ok(MailIdPage {
            messages,
            next_page: text_of(listed.get("@odata.nextLink")),
        })
    }

    /// The source's folders, read once.
    fn tree(&self, source: &MailSyncSource) -> Result<FolderTree> {
        if let Some(tree) = self.folders.borrow().get(&source.source_ref) {
            return Ok(tree.clone());
        }
        let tree = self.read_tree(source)?;
        self.folders
            .borrow_mut()
            .insert(source.source_ref, tree.clone());
        Ok(tree)
    }

    /// The source's folders, read again when `folder` is one the held read
    /// does not know and was not read again for already.
    fn tree_knowing(&self, source: &MailSyncSource, folder: &str) -> Result<FolderTree> {
        let tree = self.tree(source)?;
        let met = (source.source_ref, folder.to_owned());
        if folder.is_empty() || tree.knows(folder) || self.reread.borrow().contains(&met) {
            return Ok(tree);
        }
        let tree = self.reread_tree(source)?;
        self.reread.borrow_mut().insert(met);
        Ok(tree)
    }

    /// The source's folders read again, and held.
    fn reread_tree(&self, source: &MailSyncSource) -> Result<FolderTree> {
        let tree = self.read_tree(source)?;
        self.folders
            .borrow_mut()
            .insert(source.source_ref, tree.clone());
        Ok(tree)
    }

    /// Every mail folder of the source with its parent, and the well-known
    /// ones by name.
    fn read_tree(&self, source: &MailSyncSource) -> Result<FolderTree> {
        let mut tree = FolderTree::default();
        let select = [("$select", "id".to_owned())];
        for name in WELL_KNOWN_FOLDERS {
            let url = format!("{GRAPH_ME_URL}/mailFolders/{name}");
            if let Some(folder) = self.found(source, &url, &select, PREFER_IMMUTABLE_IDS)?
                && let Some(id) = text_of(folder.get("id"))
            {
                tree.names.insert(id, name);
            }
        }
        let mut pending = vec![format!("{GRAPH_ME_URL}/mailFolders")];
        while let Some(first) = pending.pop() {
            let mut query = vec![
                ("$select", "id,parentFolderId,childFolderCount".to_owned()),
                ("$top", GRAPH_PAGE_SIZE.to_string()),
                ("includeHiddenFolders", "true".to_owned()),
            ];
            let mut link = Some(first);
            while let Some(url) = link.take() {
                let page = self
                    .found(source, &url, &query, PREFER_IMMUTABLE_IDS)?
                    .ok_or_else(|| refused("graph_mail_folders_not_found"))?;
                // A next link carries its own query.
                query.clear();
                for folder in array(&page, "value") {
                    let Some(id) = text_of(folder.get("id")) else {
                        continue;
                    };
                    if folder
                        .get("childFolderCount")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        > 0
                    {
                        pending.push(format!(
                            "{GRAPH_ME_URL}/mailFolders/{}/childFolders",
                            path_segment(&id)
                        ));
                    }
                    let parent = text_of(folder.get("parentFolderId")).unwrap_or_default();
                    tree.parents.insert(id, parent);
                    if tree.parents.len() > MAX_FOLDERS {
                        return Err(refused("graph_mail_more_folders_than_tracked"));
                    }
                }
                link = text_of(page.get("@odata.nextLink"));
            }
        }
        Ok(tree)
    }

    /// What a message a folder reported removed became: gone, or moved
    /// under Deleted Items or Junk Email, it is deleted at the provider;
    /// anywhere else it only moved. One that left a folder not copied
    /// (`from_skipped`) for a copied folder is filed into the mailbox.
    fn removal(
        &self,
        source: &MailSyncSource,
        provider_id: String,
        from_skipped: bool,
    ) -> Result<Vec<MailHistoryChange>> {
        let select = [("$select", "id,parentFolderId,categories".to_owned())];
        let Some(message) = self.found(
            source,
            &message_url(&provider_id)?,
            &select,
            PREFER_IMMUTABLE_IDS,
        )?
        else {
            return Ok(vec![MailHistoryChange::Deleted { provider_id }]);
        };
        let folder = text_of(message.get("parentFolderId")).unwrap_or_default();
        let tree = self.tree_knowing(source, &folder)?;
        let trash = tree.trash(&folder)?;
        if from_skipped && tree.skipped(&folder)? {
            // Moved from one folder not copied to another.
            return Ok(Vec::new());
        }
        let mut changes = vec![MailHistoryChange::Labels {
            labels: folder_labels(&message, tree.names.get(&folder).copied(), &folder),
            trash_or_spam: trash,
            provider_id: provider_id.clone(),
        }];
        if from_skipped {
            changes.push(MailHistoryChange::Added(MailMessageRef {
                provider_id,
                thread_id: None,
            }));
        }
        Ok(changes)
    }
}

impl MailProviderWire for HttpGraphMailWire<'_> {
    fn current_anchor(&self, source: &MailSyncSource) -> Result<String> {
        let tree = self.reread_tree(source)?;
        let mut anchor = GraphAnchor::default();
        // No round is read here: each folder's first round, read by the
        // change feed page by page, lists the mail the copy setting keeps.
        for folder in tree.parents.keys() {
            if tree.skipped(folder)? {
                anchor.skipped.insert(folder.clone());
            }
            anchor.folders.insert(folder.clone(), delta_link(folder)?);
        }
        encode(&anchor)
    }

    fn list_page(
        &self,
        source: &MailSyncSource,
        query: &MailListQuery,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        let (url, params) = match page {
            Some(next) => (next.to_owned(), Vec::new()),
            None => {
                let mut params = vec![
                    (
                        "$select",
                        "id,conversationId,parentFolderId,isDraft".to_owned(),
                    ),
                    ("$orderby", "receivedDateTime desc".to_owned()),
                    ("$top", GRAPH_PAGE_SIZE.to_string()),
                ];
                if let Some(newer_than) = query.newer_than {
                    params.push((
                        "$filter",
                        format!("receivedDateTime ge {}", graph_time(newer_than)?),
                    ));
                }
                (format!("{GRAPH_ME_URL}/messages"), params)
            }
        };
        self.listed_messages(source, &url, &params)
    }

    fn search_page(
        &self,
        source: &MailSyncSource,
        query: &str,
        limit: u32,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        // Graph's `$search` takes the query quoted, and orders the hits by
        // relevance itself (it takes no `$orderby`).
        let messages = format!("{GRAPH_ME_URL}/messages");
        let (url, params) = match page {
            // The caller hands back the next link: it reads this mailbox's
            // messages, or nothing is read.
            Some(next) => {
                if !next
                    .strip_prefix(messages.as_str())
                    .is_some_and(|rest| rest.starts_with('?'))
                {
                    return Err(refused("graph_mail_search_page_not_this_mailbox"));
                }
                (next.to_owned(), Vec::new())
            }
            None => (
                messages,
                vec![
                    (
                        "$select",
                        "id,conversationId,parentFolderId,isDraft".to_owned(),
                    ),
                    (
                        "$search",
                        format!("\"{}\"", query.replace('\\', "\\\\").replace('"', "\\\"")),
                    ),
                    ("$top", limit.to_string()),
                ],
            ),
        };
        self.listed_messages(source, &url, &params)
    }

    fn headers(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        let select = [("$select", MESSAGE_FIELDS.to_owned())];
        match self.found(
            source,
            &message_url(provider_id)?,
            &select,
            PREFER_IMMUTABLE_IDS,
        )? {
            Some(message) => {
                let folder = text_of(message.get("parentFolderId")).unwrap_or_default();
                headers_of(&message, &self.tree_knowing(source, &folder)?).map(Some)
            }
            None => Ok(None),
        }
    }

    fn full(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        let url = message_url(provider_id)?;
        let select = [("$select", format!("{MESSAGE_FIELDS},body"))];
        let Some(message) = self.found(source, &url, &select, PREFER_TEXT_BODY)? else {
            return Ok(None);
        };
        let folder = text_of(message.get("parentFolderId")).unwrap_or_default();
        let headers = headers_of(&message, &self.tree_knowing(source, &folder)?)?;
        let content = message
            .pointer("/body/content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let html = message
            .pointer("/body/contentType")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("html"));
        let body_text = if html {
            html_text(content)
        } else {
            tidy_text(content)
        };
        // `hasAttachments` leaves inline attachments out, so the list is
        // read for every message, each of its pages; descriptions only.
        let mut attachments = Vec::new();
        let first = [("$select", "id,name,contentType,size,isInline".to_owned())];
        let mut query: &[(&str, String)] = &first;
        let mut link = Some(format!("{url}/attachments"));
        let mut pages = 0;
        while let Some(page_url) = link.take().filter(|_| pages < MAX_ATTACHMENT_PAGES) {
            pages += 1;
            let Some(listed) = self.found(source, &page_url, query, PREFER_IMMUTABLE_IDS)? else {
                break;
            };
            // A next link carries its own query.
            query = &[];
            for attachment in array(&listed, "value") {
                let Some(id) = text_of(attachment.get("id")) else {
                    continue;
                };
                attachments.push(MailAttachmentRef {
                    part_id: id.clone(),
                    provider_attachment_id: Some(id),
                    filename: text_of(attachment.get("name")),
                    media_type: text_of(attachment.get("contentType"))
                        .unwrap_or_else(|| "application/octet-stream".to_owned()),
                    size_bytes: attachment.get("size").and_then(Value::as_u64).unwrap_or(0),
                });
            }
            link = text_of(listed.get("@odata.nextLink"));
        }
        Ok(Some(MailFull {
            headers,
            body_text: Some(body_text).filter(|text| !text.is_empty()),
            attachments,
            content_digest: None,
        }))
    }

    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        let stood: GraphAnchor =
            serde_json::from_str(anchor).map_err(|_| refused("graph_mail_anchor_unreadable"))?;
        let folders: Vec<(&String, &String)> = stood.folders.iter().collect();
        let mut cursor: GraphHistoryCursor = match page {
            Some(page) => serde_json::from_str(page)
                .map_err(|_| refused("graph_mail_history_page_unreadable"))?,
            None => GraphHistoryCursor::default(),
        };
        let mut changes = Vec::new();
        let mut reads = 0;
        while changes.is_empty() && reads < MAX_FOLDER_READS_PER_PAGE {
            let Some((folder, delta)) = folders.get(cursor.folder).copied() else {
                break;
            };
            reads += 1;
            let was_skipped = stood.skipped.contains(folder);
            let link = cursor.link.clone().unwrap_or_else(|| delta.clone());
            let listed = match self.get(source, &link, &[], PREFER_DELTA)? {
                RestAnswer::Found(listed) => listed,
                RestAnswer::Failed { status, code }
                    if status == 410 || code.as_deref().is_some_and(sync_state_lost) =>
                {
                    return Ok(MailHistoryRead::Expired);
                }
                RestAnswer::Failed { status: 404, .. } => {
                    // The folder is gone: it leaves the anchor, and each
                    // message copied from it is looked up again.
                    if !was_skipped {
                        changes.push(MailHistoryChange::LabelGone {
                            label: self.tree(source)?.label(folder),
                        });
                    }
                    cursor.folder += 1;
                    cursor.link = None;
                    continue;
                }
                RestAnswer::Failed { status, .. } => {
                    return Err(Error::InvalidConfig(format!("graph_mail_status_{status}")));
                }
            };
            // A move of the folder itself is reconciled when the round ends.
            let tree = self.tree_knowing(source, folder)?;
            let now_skipped = tree.skipped(folder)?;
            if was_skipped && !now_skipped {
                cursor.met_copied.insert(folder.clone());
            }
            // A folder not copied is read for the mail that leaves it. Mail
            // added to a folder copied at either end of the round is filed;
            // the importer copies only what its headers allow.
            let from_skipped = was_skipped || now_skipped;
            for entry in array(&listed, "value") {
                let provider_id = graph_id(entry.get("id"))?;
                if entry.get("@removed").is_some() {
                    changes.extend(self.removal(source, provider_id, from_skipped)?);
                } else if !(was_skipped && now_skipped) {
                    // A change to a message copied already (its categories)
                    // reaches its labels, whatever its age; one not copied
                    // yet is filed when the copy setting keeps it.
                    changes.push(MailHistoryChange::Labels {
                        provider_id: provider_id.clone(),
                        labels: folder_labels(entry, tree.names.get(folder).copied(), folder),
                        trash_or_spam: tree.trash(folder)?,
                    });
                    if !older_than_kept(entry, source) {
                        changes.push(MailHistoryChange::Added(MailMessageRef {
                            provider_id,
                            thread_id: text_of(entry.get("conversationId")),
                        }));
                    }
                }
            }
            if let Some(next) = text_of(listed.get("@odata.nextLink")) {
                cursor.link = Some(next);
            } else {
                let reached =
                    text_of(listed.get("@odata.deltaLink")).unwrap_or_else(|| delta.clone());
                cursor.reached.insert(folder.clone(), reached);
                cursor.folder += 1;
                cursor.link = None;
            }
        }
        if cursor.folder >= folders.len() {
            // The round ends against the folders as they stand now.
            let tree = self.reread_tree(source)?;
            let mut reached = GraphAnchor {
                folders: cursor.reached,
                skipped: BTreeSet::new(),
            };
            // Folders made since the anchor's folders were read join it,
            // listing all their mail; one the round found gone stays out.
            for folder in tree.parents.keys() {
                if reached.folders.len() >= MAX_FOLDERS {
                    break;
                }
                if !stood.folders.contains_key(folder) && !reached.folders.contains_key(folder) {
                    reached.folders.insert(folder.clone(), delta_link(folder)?);
                }
            }
            let held: Vec<String> = reached.folders.keys().cloned().collect();
            for folder in held {
                if !tree.knows(&folder) {
                    continue;
                }
                let now_skipped = tree.skipped(&folder)?;
                let was_skipped = stood.skipped.contains(&folder);
                let held_copied = stood.folders.contains_key(&folder)
                    && (!was_skipped || cursor.met_copied.contains(&folder));
                if held_copied && now_skipped {
                    // Moved under a folder not copied: each message copied
                    // from it is looked up again.
                    changes.push(MailHistoryChange::LabelGone {
                        label: tree.label(&folder),
                    });
                }
                if stood.folders.contains_key(&folder) && was_skipped && !now_skipped {
                    // Out from under a folder not copied: its next round
                    // lists all its mail.
                    reached.folders.insert(folder.clone(), delta_link(&folder)?);
                }
                if now_skipped {
                    reached.skipped.insert(folder);
                }
            }
            return Ok(MailHistoryRead::Page(MailHistoryPage {
                changes,
                next_page: None,
                anchor: encode(&reached)?,
            }));
        }
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes,
            next_page: Some(encode(&cursor)?),
            anchor: anchor.to_owned(),
        }))
    }

    fn own_addresses(&self, source: &MailSyncSource) -> Result<Option<Vec<String>>> {
        // The mailbox's own object, on the base its mail is read from (fix
        // list row 20400); a right to send as another mailbox never counts.
        let select = [("$select", "mail,proxyAddresses".to_owned())];
        let Some(me) = self.found(source, GRAPH_ME_URL, &select, PREFER_IMMUTABLE_IDS)? else {
            return Ok(None);
        };
        Ok(Some(graph_own_addresses(&me)))
    }

    fn attachment(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        let id = attachment
            .provider_attachment_id
            .as_deref()
            .unwrap_or(attachment.part_id.as_str());
        require_graph_id(id)?;
        let url = format!(
            "{}/attachments/{}",
            message_url(provider_id)?,
            path_segment(id)
        );
        let Some(answer) = self.found(source, &url, &[], PREFER_IMMUTABLE_IDS)? else {
            return Ok(None);
        };
        // A file attachment carries its bytes; an item or reference
        // attachment carries none.
        let Some(bytes) = answer.get("contentBytes").and_then(Value::as_str) else {
            return Err(refused("graph_mail_attachment_carries_no_bytes"));
        };
        base64::engine::general_purpose::STANDARD
            .decode(bytes.trim())
            .map(Some)
            .map_err(|_| refused("graph_mail_attachment_bytes_unreadable"))
    }
}

/// A message's headers from its Graph answer, its folder counted by
/// `tree`.
fn headers_of(message: &Value, tree: &FolderTree) -> Result<MailHeaders> {
    let provider_id = graph_id(message.get("id"))?;
    let folder = text_of(message.get("parentFolderId")).unwrap_or_default();
    let class = tree.class(&folder)?;
    let internet = message.get("internetMessageHeaders");
    let header = |field: &str| header_value(internet, field).map(|value| value.trim().to_owned());
    Ok(MailHeaders {
        provider_id,
        thread_id: text_of(message.get("conversationId")),
        rfc_message_id: text_of(message.get("internetMessageId")),
        in_reply_to: header("In-Reply-To"),
        references: header("References")
            .map(|references| references.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
        from: message.pointer("/from/emailAddress").map(mailbox_text),
        to: recipients(message, "toRecipients"),
        cc: recipients(message, "ccRecipients"),
        reply_to: recipients(message, "replyTo"),
        subject: text_of(message.get("subject")),
        date: message
            .get("sentDateTime")
            .and_then(Value::as_str)
            .and_then(rfc3339_seconds),
        received_at: message
            .get("receivedDateTime")
            .and_then(Value::as_str)
            .and_then(rfc3339_seconds)
            .unwrap_or(0),
        sent_by_mailbox: class == "sentitems",
        trash_or_spam: TRASH_FOLDERS.contains(&class),
        draft: class == "drafts"
            || message
                .get("isDraft")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        labels: folder_labels(message, tree.names.get(&folder).copied(), &folder),
    })
}

/// A message's labels: its folder (by its well-known name when it has one)
/// and its categories.
fn folder_labels(message: &Value, name: Option<&'static str>, folder: &str) -> Vec<String> {
    let mut labels = vec![name.map_or_else(|| folder_label(folder), str::to_owned)];
    labels.extend(
        array(message, "categories")
            .iter()
            .filter_map(Value::as_str)
            .map(|category| format!("category:{category}")),
    );
    labels
}

/// A Graph `emailAddress` as a header writes it: `Name <address>`, or the
/// address alone. The name is written as an RFC 5322 display name
/// ([`super::mime::display_name`]), so a comma, colon or angle bracket Graph returns in
/// it never reads as a list, group or address boundary (fix list row
/// 17645).
fn mailbox_text(email: &Value) -> String {
    let address = email
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let name = email
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if name.is_empty() || name.eq_ignore_ascii_case(address) {
        address.to_owned()
    } else if address.is_empty() {
        name.to_owned()
    } else {
        format!("{} <{address}>", super::mime::display_name(name))
    }
}

fn recipients(message: &Value, key: &str) -> Vec<String> {
    array(message, key)
        .iter()
        .filter_map(|recipient| recipient.get("emailAddress"))
        .map(mailbox_text)
        .filter(|text| !text.is_empty())
        .collect()
}

/// The SMTP addresses a Graph user or group object names as its own: its
/// `mail`, and each `proxyAddresses` entry of type `smtp:` (any case, the
/// primary `SMTP:` included), the prefix stripped. Any other address type
/// (`SIP:`, `X500:`) is no mail address.
fn graph_own_addresses(me: &Value) -> Vec<String> {
    let mut own: Vec<String> = text_of(me.get("mail")).into_iter().collect();
    own.extend(array(me, "proxyAddresses").iter().filter_map(|proxy| {
        let proxy = proxy.as_str()?;
        if !proxy.get(..5)?.eq_ignore_ascii_case("smtp:") {
            return None;
        }
        Some(proxy.get(5..)?.trim().to_owned())
    }));
    own
}

/// The label a folder that is no well-known one gives its mail.
fn folder_label(folder: &str) -> String {
    format!("folder:{folder}")
}

/// The Graph user `me` is the mailbox `source` names (its `mail` or
/// `userPrincipalName`).
pub(super) fn reads_mailbox(me: &Value, source: &MailSyncSource) -> Result<()> {
    let wanted = source.address.trim();
    let reads = ["mail", "userPrincipalName"].iter().any(|field| {
        me.get(*field)
            .and_then(Value::as_str)
            .is_some_and(|address| address.trim().eq_ignore_ascii_case(wanted))
    });
    if reads {
        Ok(())
    } else {
        Err(refused("graph_mail_credential_reads_another_mailbox"))
    }
}

/// Whether a Graph error code says the delta state is lost.
fn sync_state_lost(code: &str) -> bool {
    let code = code.to_ascii_lowercase();
    code.contains("syncstate") || code == "resyncrequired"
}

/// Unix seconds as the UTC time Graph filters take.
fn graph_time(seconds: u64) -> Result<String> {
    let date = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .ok_or_else(|| refused("graph_mail_time_out_of_range"))?;
    Ok(date.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn rfc3339_seconds(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .and_then(|date| u64::try_from(date.timestamp()).ok())
}

/// The first link of a folder's delta round: all its mail, each entry with
/// its receive time, so the copy setting's cutoff is applied as each page is
/// read, under the setting that stands then.
fn delta_link(folder: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(&format!(
        "{GRAPH_ME_URL}/mailFolders/{}/messages/delta",
        path_segment(folder)
    ))
    .map_err(|_| refused("graph_mail_folder_link_unreadable"))?;
    url.query_pairs_mut()
        .append_pair("$select", "id,conversationId,receivedDateTime,categories");
    Ok(url.into())
}

/// Whether a change-feed entry is mail the copy setting does not keep:
/// received before its cutoff.
fn older_than_kept(entry: &Value, source: &MailSyncSource) -> bool {
    source.newer_than.is_some_and(|cutoff| {
        entry
            .get("receivedDateTime")
            .and_then(Value::as_str)
            .and_then(rfc3339_seconds)
            .is_some_and(|received| received < cutoff)
    })
}

/// A message's Graph URL, its id escaped as one path segment.
fn message_url(provider_id: &str) -> Result<String> {
    require_graph_id(provider_id)?;
    Ok(format!(
        "{GRAPH_ME_URL}/messages/{}",
        path_segment(provider_id)
    ))
}

/// A Graph id: printable ASCII, no spaces, bounded.
fn graph_id(value: Option<&Value>) -> Result<String> {
    let id = value.and_then(Value::as_str).unwrap_or_default();
    require_graph_id(id)?;
    Ok(id.to_owned())
}

fn require_graph_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_GRAPH_ID_BYTES
        || !id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(refused("graph_mail_id_not_plain"));
    }
    Ok(())
}

/// `text` percent-escaped as one URL path segment.
pub(super) fn path_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn encode(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|_| refused("graph_mail_state_unencodable"))
}
