//! The owner surface in the OpenAPI document (FIX 1755): every `/v1/owner`
//! route, with the SDK row whose input it takes where it mirrors one. The
//! routes are axum handlers with no utoipa annotation, so this table names
//! them; a route added under `api/owner_routes` adds its line here.

use serde_json::{Map, Value, json};

/// One `/v1/owner` route: its method, its path under `/v1/owner`, what it
/// does, and the SDK row whose input schema its body is.
pub(crate) struct OwnerRoute {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) row: Option<&'static str>,
}

/// Every `/v1/owner` route, the off-record ones included.
pub(crate) const OWNER_ROUTES: &[OwnerRoute] = &[
    OwnerRoute {
        method: "get",
        path: "/authority/handoff-alarms",
        summary: "Every saved alarm in the shape and order vault.authority.handoff_alarms answers (OF-158): unix seconds, oldest raised first, then by signer.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/authority/handoff-alarms/acknowledge",
        summary: "The owner has seen one alarm.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/backups",
        summary: "List backups.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/backups",
        summary: "Take backup.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/backups/rehearse",
        summary: "Rehearse backup.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/cleanup",
        summary: "Cleanup review.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/cleanup",
        summary: "Configure cleanup.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/cleanup/accept",
        summary: "Accept cleanup.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/cleanup/reject",
        summary: "Reject cleanup.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/cleanup/restore",
        summary: "Restore archived.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/coach/code-fixes",
        summary: "The Coach's code-fix work, newest first (at most 256).",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/coach/judge-asks/minutes",
        summary: "The caller's remaining judge-ask minutes; zero until they fund some.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/coach/judge-asks/minutes",
        summary: "Sets the caller's balance.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/coach/judge-asks/pick",
        summary: "The caller's pick on an ask their digest delivered, a final label in the judged skill's anchor.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/coach/judge-asks/regrade",
        summary: "The caller's re-grade of a pick a judge rubric edit left waiting: kept, or its case asked again.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/coach/training-offers",
        summary: "The offers awaiting the owner.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/coach/training-offers/answer",
        summary: "The owner's answer to the exact offer they saw.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/coach/training-offers/undo",
        summary: "The owner's undo of the stock switch an approved offer bound.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/commitments/reminder-route",
        summary: "Reminder route.",
        row: None,
    },
    OwnerRoute {
        method: "put",
        path: "/commitments/reminder-route",
        summary: "Set reminder route.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/conflicts",
        summary: "Every unanswered contradiction, oldest first.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/conflicts/revert",
        summary: "The owner's revert of one settlement.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/conflicts/review",
        summary: "Ends the owner's hold on the Dreamer's review of one subject or of every subject in the vault, so it settles them through its ladder again.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/conflicts/review/revoke",
        summary: "Holds the Dreamer's review on exactly that scope; it leaves those conflicts here for the owner until /review ends the hold.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/conflicts/settle",
        summary: "The owner's answer to one marker.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/conflicts/settled",
        summary: "The standing settlements, the Dreamer's among them, newest first.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/connectors/consent",
        summary: "The connector's tool rows, the actor's live grant per row, and the installed endpoint.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/consent",
        summary: "Grants the named tool rows to one actor (a held call's, a named one, else the owner's) at the installed endpoint.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/enabled",
        summary: "The owner's on/off switch for an admitted connector.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/proxy",
        summary: "Admits the OpenAI proxy for one paired actor.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/qualify",
        summary: "Runs the probe suite through the installed endpoint with the owner's kit, activates the key, and approves the exact manifest the suite ran on.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/refresh",
        summary: "Lists the connector's tools again, at its pinned revision while it still answers that one.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/register",
        summary: "Lists the connector's tools at its installed endpoint, screens and resolves them, drafts the grant slate and registers the key Pending at the negotiated revision.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/connectors/setup",
        summary: "The connector's key, its admission state and its grant slate, for a resumed setup.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/slate/accept",
        summary: "The owner's stamp on the connector's slate, at the revision reviewed.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/connectors/subscriptions",
        summary: "The agent's connector event subscriptions, standing and revoked.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/subscriptions",
        summary: "Subscribes the agent to the messages the channel's built-in pack routes to it.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/connectors/subscriptions/revoke",
        summary: "The subscription wakes nothing more; its key stays.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/courtesy-delete/answer",
        summary: "The owner's answer to one ask, with the reason typed on the card when there is one.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/courtesy-delete/incoming",
        summary: "Incoming.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/courtesy-delete/send",
        summary: "Send.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/courtesy-delete/sent",
        summary: "Sent.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/decisions/asks",
        summary: "The asks after after, oldest first.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/decisions/asks/answer",
        summary: "The owner's answer to one ask, with the reason typed on the card when there is one.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/decisions/rules",
        summary: "Every host rule row at its latest revision, revoked ones included.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/decisions/rules/revoke",
        summary: "The owner revokes one rule row, so it answers nothing; the next ask of its question goes up the ladder.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/desktops",
        summary: "Each bound run desktop whose guest started, with who has it, the agent's ask while it waits, and the holder's count of inputs.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/desktops/input",
        summary: "One click, type, key, hotkey or scroll from the owner who holds the desktop, at the pixels of the screen they were last shown.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/desktops/return",
        summary: "The owner hands the desktop back, from holding it or from the agent's ask unanswered.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/desktops/screen",
        summary: "The whole display as a PNG, unmasked, for the owner only: never kept, never a receipt.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/desktops/stream",
        summary: "The run desktop's whole display as server-sent events while the owner watches or holds it: state, frame (changed PNGs as base64, paced), error, ended and refused events.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/desktops/take",
        summary: "The owner holds the run's desktop, asked or not, once the agent's call in flight ends.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/diary/grants",
        summary: "A diary.read Grant for one reader.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/diary/read",
        summary: "The owner reads a diary under its Grant.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/diary/review",
        summary: "Whether an agent reviews each read first.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/attendee",
        summary: "The owner's answer to one unknown-attendee ask, once.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/confirm",
        summary: "The owner's answer to one frozen offer, against the exact delta it was shown.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/disclosure/entry",
        summary: "One attendee's first entry into a chat or room, the P5 question the owner answers once.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/entry/confirm",
        summary: "The owner's yes to one entry's P5 question: the entry's contact is cleared standing under the frozen offer, the entry sees the history chosen, and the entry is decided once.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/entry/decline",
        summary: "The owner's no to one entry's P5 question: the offer settles denied, nothing widens, and the entry is decided once.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/disclosure/mode",
        summary: "The disclosure-mode knob, auto when never set.",
        row: None,
    },
    OwnerRoute {
        method: "put",
        path: "/disclosure/mode",
        summary: "Turns the knob.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/narrow",
        summary: "Narrows a contact's standing clearance to a Scope inside the current one.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/disclosure/offer",
        summary: "One frozen contact-disclosure offer, the private ask the owner answers.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/preclear",
        summary: "The owner clears a named trusted set for one Scope in advance, each contact with its own receipt.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/disclosure/revoke",
        summary: "Consent.revoke_contact_disclosure, the one-tap revoke of a contact's standing clearance.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/dreamer/changes",
        summary: "The Dreamer's standing changes, newest first, and the people whose about it wrote.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/dreamer/maintenance/applied",
        summary: "Every applied write, reverted ones too, newest first.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/dreamer/maintenance/revert",
        summary: "The owner's revert of one applied write.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/dreamer/revert",
        summary: "The owner's revert of one Dreamer change, with one receipt.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/embedding-spaces",
        summary: "Every unanswered contradiction, oldest first.",
        row: Some("vault.embedding_spaces.list"),
    },
    OwnerRoute {
        method: "put",
        path: "/embedding-spaces",
        summary: "Declares or widens one space; a new width is a new space.",
        row: Some("vault.embedding_spaces.declare"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/bind",
        summary: "Binds one kind slot, or returns it to its default.",
        row: Some("vault.embedding_spaces.bind"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/move",
        summary: "Starts moving every slot the incumbent serves to the candidate.",
        row: Some("vault.embedding_spaces.move"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/move/abandon",
        summary: "Ends an open move with no swap.",
        row: Some("vault.embedding_spaces.move_abandon"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/move/approve",
        summary: "The owner's yes over a check that did not read not worse.",
        row: Some("vault.embedding_spaces.move_approve"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/move/check",
        summary: "Runs the move's probes now, through both spaces' towers, and acts on the reading.",
        row: Some("vault.embedding_spaces.move_check"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/move/undo",
        summary: "Binds a swapped-in move's incumbent again.",
        row: Some("vault.embedding_spaces.move_undo"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/one-space",
        summary: "The one-space preset.",
        row: Some("vault.embedding_spaces.one_space"),
    },
    OwnerRoute {
        method: "get",
        path: "/embedding-spaces/probes",
        summary: "Probes.",
        row: Some("vault.embedding_spaces.probes.list"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/probes",
        summary: "Stores one probe the owner, or another model, wrote.",
        row: Some("vault.embedding_spaces.probes.put"),
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/probes/delete",
        summary: "Delete probe.",
        row: Some("vault.embedding_spaces.probes.delete"),
    },
    OwnerRoute {
        method: "get",
        path: "/embedding-spaces/refused",
        summary: "Every document the space's model refused by its content, with the reason and when.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/refused/clear",
        summary: "Forgets one refusal, so the backfill sends the same bytes to the space's model again.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/embedding-spaces/retire",
        summary: "Drops a space no slot binds and no open move names, with its rows.",
        row: Some("vault.embedding_spaces.retire"),
    },
    OwnerRoute {
        method: "get",
        path: "/federation/connect",
        summary: "This vault's id and host key, what a peer's owner names to offer it a pact.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/federation/connect/accept",
        summary: "Logs the Connect the peer's half signs and answers this host's half of the same pact.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/federation/connect/offer",
        summary: "This host's signed half of a new pact with a peer vault, for the owner to carry to the peer.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/federation/grant-travel",
        summary: "Binds or clears one live grant's travel choice.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/federation/peer-confidence",
        summary: "Every owner-set scale.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/federation/peer-confidence",
        summary: "Sets or clears one peer's scale.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/feedback/inbox",
        summary: "Feedback inbox.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/feedback/preview",
        summary: "Preview feedback.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/feedback/send",
        summary: "Send feedback.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/graph-fs",
        summary: "Read graph fs.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/guests/revoke",
        summary: "\"<hex>\"}: an unknown or non-guest grant is not found, and a disconnect the fold refuses fails the whole revoke.",
        row: Some("vault.guests.revoke"),
    },
    OwnerRoute {
        method: "get",
        path: "/healer/failures",
        summary: "Healer failures.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/healer/failures/drill",
        summary: "Drill failure.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/healer/oversight",
        summary: "Healer oversight.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/history",
        summary: "Every history erase filed for one text.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/history/erase",
        summary: "Drops one text's history below its oldest pin, or below through when that is no later.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/history/erase/execute",
        summary: "Runs a waiting history erase the caller started, once its veto window passed with no objection.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/identity/asks",
        summary: "Every open identity ask, each with its one-tap choice card.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/identity/asks/answer",
        summary: "The owner's choice on one ask.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/imports/approve",
        summary: "Approve import.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/imports/decline",
        summary: "Decline import.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/imports/preview",
        summary: "Preview import.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/inbox",
        summary: "One page of the lens, filtered to an identity or to one agent's slice when asked.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/inbox/concern",
        summary: "One card, with the run its attempt is in and that attempt's node marked.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/inbox/concern/move",
        summary: "Takes one of the card's moves.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/inbox/concern/outcome",
        summary: "Sets one card's outcome.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/legal-holds",
        summary: "Every customer hold, and each host order the owner may be told of, without its order reference or operator.",
        row: Some("vault.legal_holds.list"),
    },
    OwnerRoute {
        method: "post",
        path: "/legal-holds",
        summary: "Places the owner's customer hold on targets, with an optional opaque matter_ref.",
        row: Some("vault.legal_holds.place"),
    },
    OwnerRoute {
        method: "get",
        path: "/legal-holds/lift-and-erase",
        summary: "The confirm's title and prompt, exactly as the engine words them (C7).",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/legal-holds/lift-and-erase",
        summary: "The owner's one confirm.",
        row: Some("vault.legal_holds.lift_and_erase"),
    },
    OwnerRoute {
        method: "get",
        path: "/legal-holds/log",
        summary: "The owner-visible hold log, oldest first: ids, times and reason codes.",
        row: Some("vault.legal_holds.log"),
    },
    OwnerRoute {
        method: "post",
        path: "/legal-holds/widen",
        summary: "Adds targets to the owner's standing hold hold_id.",
        row: Some("vault.legal_holds.widen"),
    },
    OwnerRoute {
        method: "post",
        path: "/maintain",
        summary: "Every housekeeping sweep now, due or not, as oneiron maintain runs them on a stopped vault.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/model-catalog",
        summary: "The catalog ref's sync policy, the revisions it has seen and trusted, and the installed pack.",
        row: None,
    },
    OwnerRoute {
        method: "put",
        path: "/model-catalog",
        summary: "Move the catalog ref's policy.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/model-catalog/sync",
        summary: "Fetch the catalog at its ref's policy and install it.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/notes/tombstones",
        summary: "Note tombstone review.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/notes/tombstones/accept",
        summary: "Accept note tombstone.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/notes/tombstones/decline",
        summary: "Decline note tombstone.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/off-record",
        summary: "Off record session.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/off-record",
        summary: "Enter off record.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/off-record/close",
        summary: "Close off record.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/off-record/mode",
        summary: "Flip off record.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/off-record/promote",
        summary: "Promote off record.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/off-record/save",
        summary: "Save off record.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/off-record/witness",
        summary: "Witness off record.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/origin-authority",
        summary: "Origin authority.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/origin-authority",
        summary: "Cut origin authority.",
        row: None,
    },
    OwnerRoute {
        method: "delete",
        path: "/origin-mirror",
        summary: "Clear origin mirror.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/origin-mirror",
        summary: "Origin mirror.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/origin-mirror",
        summary: "Set origin mirror.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/origin-mirror/push",
        summary: "Push origin mirror.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/pack-drift",
        summary: "Pack drift repairs.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs",
        summary: "Every active installation.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs",
        summary: "Install a pack folder, or replace the one under its name.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/agent/world",
        summary: "The owner's answer to a travelling AgentPack held for its world (needs_world).",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/defaults/import",
        summary: "Import hub skill.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/defaults/restore",
        summary: "Restore defaults.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/defaults/restore-skill",
        summary: "Restore hub skill.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs/hooks",
        summary: "Every hook binding, enabled or not.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/hooks/bind",
        summary: "The owner's consent binds an installed pack's hooks; a hub install never does by itself.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/hooks/enabled",
        summary: "The owner's dial on one binding.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/hooks/qualify",
        summary: "A Candidate hub pack's hooks take their test, a replay over past entries that lands nothing.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/install",
        summary: "Fetch a pack from a configured hub at a pin and install it.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs/organs",
        summary: "Every organ of an Active installation, with the platforms this vault holds a build for.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/organs/build",
        summary: "Hold one organ build for a staged pack source.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs/ref-sync",
        summary: "The ref's stored policy, or null when it follows its installed pin.",
        row: None,
    },
    OwnerRoute {
        method: "put",
        path: "/packs/ref-sync",
        summary: "Set one ref's policy and pin.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/remove",
        summary: "The owner removes an installed pack.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs/setup",
        summary: "The owner's guided setup of one pack (OF-378), readable while the pack is still a Candidate.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/setup/answer",
        summary: "One typed answer, or one card action.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/setup/prepare",
        summary: "Open, or resume, the setup.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/setup/verify",
        summary: "Check one connection before the pack uses it.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/import",
        summary: "Import a shipped library skill, or a hub skill at a pin.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/restore",
        summary: "Re-import a deleted or retired library skill as a fresh Candidate; an unchanged one is left alone.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/restore-defaults",
        summary: "Restore every missing or retired embedded default as a fresh Candidate.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/{entity}/activation/approve",
        summary: "The owner's consent to the ask they were shown.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/{entity}/activation/prepare",
        summary: "The immutable held-out activation ask for a hub Candidate.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/{entity}/permissions/approve",
        summary: "The owner's answer to a hub skill's permission ask; it activates the Candidate.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs/skills/{entity}/receipts",
        summary: "Skill receipts.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/skills/{entity}/sync",
        summary: "Refetch a hub skill at its ref's stored policy.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/slack/install",
        summary: "One link that installs the Slack app to the owner's workspace (OF-519).",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/packs/slack/manifest",
        summary: "The Slack app manifest at this host's public origin, to paste at api.slack.com/apps (OF-519).",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/packs/sync",
        summary: "Refetch an installed hub pack at its ref's policy and install it.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/pads/read",
        summary: "The owner reads an agent's sealed pads.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/persona",
        summary: "Preview persona.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/persona/export",
        summary: "Export persona.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/proactivity/action-mode",
        summary: "The owner's action-mode policy.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/proactivity/action-mode",
        summary: "Replaces the whole policy.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/proactivity/digest",
        summary: "One delivered digest, verified against its id.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/proactivity/digest/assemble",
        summary: "The caller's own digest, assembled now: what a due regular digest carries, and once a cadence period the judge calibration asks their funded minutes buy, which no other digest delivers.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/recovery-kit",
        summary: "The kits this vault issued, the current one, and each private world's no-kit state here.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/representation",
        summary: "One drafted follow-up, as approval would send it.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/representation/approve",
        summary: "Approves the draft and schedules it.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/representation/decline",
        summary: "Declines the draft for good.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/runs",
        summary: "Pending runs.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/runs/approve",
        summary: "Approve run.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/runs/decline",
        summary: "Decline run.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/runs/hold",
        summary: "The run's hold, with whether its spend scope has spend left read again now.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/runs/hold/resume",
        summary: "{run}: resumes the held run as the owner.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/runs/review",
        summary: "Review run.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/secret-scan",
        summary: "Secret scan.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secret-scan",
        summary: "Set secret scan.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/bind",
        summary: "With {\"handle\"} or {\"name\"}, \"effector\", and optionally \"tier_ceiling\" and \"scopes\".",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/secrets/found",
        summary: "Each record the write door lifted keys out of, newest first, with its keys.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/found/delete",
        summary: "Deletes the record or file the key sits in (a hard delete, with its redaction receipt) and settles every key found there.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/found/grant",
        summary: "A standing grant to that agent on the key's class, in that project, until revoked.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/found/not-a-secret",
        summary: "The owner overrules the scan for that key in its record.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/secrets/lift",
        summary: "The run in progress, the last run's receipt and the open proposals, counted by cause.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/lift/close",
        summary: "Closes one open proposal, by its id, and returns it as it now stands.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/register",
        summary: "The body is read by RegisterSecret::read, as rotation's is: the owner door runs first, so a refused caller's body is never read.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/reveal",
        summary: "The owner reads one secret's value.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/secrets/reveals",
        summary: "The vault's reveals, newest first, each with its receipt and, while it waits on the owner, its ask card and digest.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/reveals/answer",
        summary: "The owner's answer to one asked reveal, against the exact digest it was listed with.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/revoke",
        summary: "The record goes terminal and every lease over it is revoked (OF-422).",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/secrets/rotate",
        summary: "The body is read by RotateSecret::read, not Json: the extractor's body copy and parser scratch would outlive the request unwiped.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/self-heal/findings",
        summary: "One detector's raised T3 findings, newest first, each with the owner's label.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/self-heal/findings/label",
        summary: "The owner's one label on a raised T3 finding.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/self-heal/minted",
        summary: "Each family's registered T2, by family.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/settings/learning",
        summary: "The catalog, each knob with the value the vault reads now, and the owner's rows.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/settings/learning",
        summary: "Lays one seed or pin, replacing the row of the same key, mode and scope.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/settings/learning/clear",
        summary: "Clears one row; an absent row clears too.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/settings/models",
        summary: "The connector's tool rows, the actor's live grant per row, and the installed endpoint.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/settings/models",
        summary: "Sets the switch; the next Responses turn reads it.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/decisions",
        summary: "The newest journal rows.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/goal-project",
        summary: "The project a skill's goal is joined to.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/goal-project",
        summary: "Joins a skill's goal to a project's goal record, or unbinds it.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/goal-revisions",
        summary: "The preferences the loop proposes for the project's goal in force, oldest first, for its goal interview to show.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/measure",
        summary: "Measures an open proposal on its goal's plan with the registered judge and live arms, and keeps the report for the gate.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/pairs",
        summary: "Every pick the owner made between a blind preference pair's two responses.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/pairs/pick",
        summary: "The owner's pick between a blind preference pair's two responses.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/person-time",
        summary: "One act's minutes on a run.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/preferences",
        summary: "The tradeoff rules of a skill's goal, the ones its responsible person's picks taught included.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/swap-policy",
        summary: "The tie-breakers, the pinned divergence rate and the hands-on setting in force.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/swap-policy",
        summary: "Replaces the swap policy; a field left out takes its default.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/swaps",
        summary: "The incumbent judge, the swap policy and every swap receipt, each disagreement's ruling included.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/swaps/pick",
        summary: "The owner's hand-test pick on one disagreement.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/skills/judge/tradeoff-asks",
        summary: "The tradeoff asks that have climbed to a role the owner holds.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/skills/judge/tradeoff-asks/pick",
        summary: "The owner's A/B pick.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/space-posting",
        summary: "One space's dial.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/space-posting",
        summary: "Sets one space's dial, and with grant the exact owner-space consent it needs.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/status",
        summary: "The kits this vault issued, the current one, and each private world's no-kit state here.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/steer",
        summary: "The steer verb's input (task_ref, instruction, key) and its receipt.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/stewardship",
        summary: "The owner's keep-in-touch rules.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/stewardship",
        summary: "Replaces the whole rule set.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/vault-key",
        summary: "Whether the vault has a data key, whether this server holds it, and its wraps, each passkey's with its PRF input.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/vault-key/device",
        summary: "Wraps the vault key to this install's keystore.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/vault-key/passkeys",
        summary: "Wraps the vault key to a passkey by its PRF output.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/vault-key/password",
        summary: "Sets the vault password, replacing an earlier one.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/vault-key/prf-input",
        summary: "The PRF input a passkey of that name is asked at.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/vault-key/remove",
        summary: "Removes one wrap; the last one stays.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/vault-key/retire-escrow",
        summary: "Retires an escrow recipient whose secret was released.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/vault-key/signer",
        summary: "This install's checkpoint signer, the pin another host trusts this vault's backups by.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/vault-key/unlock",
        summary: "Holds the vault key on this server, from the password or a passkey's PRF output.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/weave/digest",
        summary: "The owner's digest.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/weave/lens",
        summary: "The owner lens, live, rendered through the weave-report skill on this server's Dreamer narrative route, as a card whose frame this server holds for the credential's events on it.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/weave/link/wrong",
        summary: "The owner labels a link it sees in the owner lens as wrong.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/weave/report",
        summary: "The owner lens, live.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/weave/schedules",
        summary: "Every reader's digest schedule.",
        row: None,
    },
    OwnerRoute {
        method: "put",
        path: "/weave/schedules",
        summary: "One reader's cadence, first due second and sections.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/weave/schedules/clear",
        summary: "Stop one reader's digests.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/widen-proposals",
        summary: "The proposals, newest first.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/widen-proposals/approve",
        summary: "Widens the parent's slice and enqueues the child.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/widen-proposals/decline",
        summary: "Refuses the proposal for good.",
        row: None,
    },
    OwnerRoute {
        method: "get",
        path: "/wire-health",
        summary: "Every check this server keeps.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/wire-health/outcome",
        summary: "What happened next to one crossing.",
        row: None,
    },
    OwnerRoute {
        method: "post",
        path: "/workspace/finish",
        summary: "\"<ref>\"}: a repeat leaves the root as the first finish signed it.",
        row: None,
    },
];

/// Adds each owner route to `spec`'s paths: owner-grade bearer, its row's
/// input schema as the JSON body where it has one, an object answer, and the
/// one 403 the owner door answers every refusal with.
pub(crate) fn merge_owner_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for route in OWNER_ROUTES {
        let path = format!("/v1/owner{}", route.path);
        let item = paths
            .entry(path.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut();
        let Some(item) = item else {
            continue;
        };
        item.insert(route.method.to_owned(), operation(route, &path));
    }
}

fn operation(route: &OwnerRoute, path: &str) -> Value {
    let mut operation = Map::new();
    operation.insert("tags".to_owned(), json!(["owner"]));
    operation.insert("summary".to_owned(), json!(route.summary));
    operation.insert(
        "operationId".to_owned(),
        json!(format!(
            "owner_{}_{}",
            route.method,
            path.trim_start_matches("/v1/owner/")
                .replace(['/', '-', '{', '}'], "_")
        )),
    );
    operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
    let parameters: Vec<Value> = path
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}}))
        .collect();
    if !parameters.is_empty() {
        operation.insert("parameters".to_owned(), Value::Array(parameters));
    }
    if matches!(route.method, "post" | "put") {
        let schema = route
            .row
            .and_then(oneiron::task_verb::sdk::input_schema)
            .cloned()
            .unwrap_or_else(|| json!({"type": "object"}));
        operation.insert(
            "requestBody".to_owned(),
            json!({"required": true, "content": {"application/json": {"schema": schema}}}),
        );
    }
    let mut answer = json!({
        "description": "The owner action's answer.",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    if let Some(row) = route.row {
        answer["description"] = json!(format!(
            "The `{row}` row's answer, as its verb hooks' post chain left it."
        ));
    }
    operation.insert(
        "responses".to_owned(),
        json!({
            "200": answer,
            "403": {
                "description": "Not the vault's live owner, on an owner-grade slip: one refusal for every failed check.",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}
            }
        }),
    );
    Value::Object(operation)
}

/// A removed device's own routes (OF-150, OF-158, FIX 1300): no bearer, as
/// its slips are revoked; the revoked slip rides `x-oneiron-left-slip`, with
/// its holder proof in `x-oneiron-binding`, and each call spends its nonce.
const LEFT_SLIP_ROUTES: &[(&str, &str)] = &[
    (
        "/v1/shared/left-notices",
        "The removed person's own loss-of-access notices, each signed by this host's root key.",
    ),
    (
        "/v1/shared/removal-export",
        "Every archive export-first removals delivered to the removed person, still within its term.",
    ),
    (
        "/v1/shared/removal-export/{receipt_id}",
        "The one archive the removal receipt receipt_id delivered to the removed person, while within its term; not found after it.",
    ),
];

/// Adds the removed device's routes to `spec`'s paths.
pub(crate) fn merge_left_slip_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for (path, summary) in LEFT_SLIP_ROUTES {
        let mut parameters = vec![
            json!({"name": "x-oneiron-left-slip", "in": "header", "required": true, "schema": {"type": "string"}, "description": "The revoked slip this vault minted for the person."}),
            json!({"name": "x-oneiron-binding", "in": "header", "required": true, "schema": {"type": "string"}, "description": "The slip holder's proof over the request's timestamp and nonce."}),
        ];
        if path.ends_with("{receipt_id}") {
            parameters.push(json!({"name": "receipt_id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The removal receipt's id, 32 hex."}));
        }
        let operation = json!({
            "tags": ["shared"],
            "summary": summary,
            "operationId": format!("left_slip_{}", path.trim_start_matches("/v1/shared/").replace(['/', '-', '{', '}'], "_")),
            "parameters": parameters,
            "responses": {
                "200": {"description": "The removed person's answer.", "content": {"application/json": {"schema": {"type": "object"}}}},
                "401": {"description": "The slip or its proof does not verify, or the nonce was spent.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}},
                "404": {"description": "No archive this receipt delivered to the person is within its term.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}}
            }
        });
        if let Some(item) = paths
            .entry((*path).to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
        {
            item.insert("post".to_owned(), operation);
        }
    }
}
