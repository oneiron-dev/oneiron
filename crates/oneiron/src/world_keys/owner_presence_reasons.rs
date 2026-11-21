//! The one line each owner door hands the device's prompt (row
//! OWNER-CONFIRM-SHEET): what the person at the device is asked to confirm.
//! A platform prompt puts the application's name and "is trying to" before
//! the line, so each starts with a verb and ends with no period. These are
//! the engine's words until the owner fixes them.

pub(crate) const ACCEPT_PACK_DEFAULTS: &str = "accept new default settings";
pub(crate) const AGENT_WORLD_ACCESS: &str = "change which worlds an agent can access";
pub(crate) const ANSWER_ATTENDEE_ASK: &str = "confirm who a speaker is";
pub(crate) const ANSWER_CODE_CONSENT_ASK: &str = "approve an action an agent is waiting to take";
pub(crate) const ANSWER_COMM_WIDEN_ASK: &str = "let an agent message more recipients";
pub(crate) const ANSWER_LIVE_EDIT_ASK: &str = "let someone edit a document as you";
pub(crate) const ANSWER_TRAINING_OFFER_ASK: &str = "approve an offered AI model change";
pub(crate) const ANSWER_TRAINING_SWAP_ASK: &str = "switch to a newly trained AI model";
pub(crate) const BOARD_LAYOUT: &str = "change the board layout";
pub(crate) const CANCEL_RECOVERY_HOLD: &str = "cancel a waiting recovery of this vault";
pub(crate) const CHANGE_SHARED_MEMBER_ROLE: &str = "change a member's role in the shared vault";
pub(crate) const CHECKPOINT_POLICY: &str = "change which devices vouch for this vault";
pub(crate) const CONFIRM_HELD_MACHINE_ANSWERS: &str = "approve pending changes to linked devices";
pub(crate) const CONFIRM_OWNER_PASSKEY: &str = "confirm a passkey that another passkey added";
pub(crate) const CONFIRM_OWNER_SIGNING_KEY: &str = "confirm a device that a passkey added";
pub(crate) const CONFIRM_RECOVERY_HOLD: &str = "approve a waiting recovery of this vault";
pub(crate) const CONVERSATION_LEARNING: &str = "change whether this vault learns from messages";
pub(crate) const CONVERSATION_TRAINING: &str = "change whether your messages are used for training";
pub(crate) const DEFAULT_FACET: &str = "change where new memories are saved by default";
pub(crate) const DREAMER_WAKE_POLICY: &str = "change when background work runs";
pub(crate) const ENROLL_MACHINE: &str = "add or change a device linked to this vault";
pub(crate) const ENROL_OWNER_PASSKEY: &str = "add a passkey that can approve changes";
pub(crate) const ENROL_OWNER_SIGNING_KEY: &str = "add a device that can approve changes";
pub(crate) const ENROL_RECOVERY_AUTHORITY_KEY: &str = "let your recovery kit approve changes";
pub(crate) const ENROL_THIS_DEVICE_OWNER_SIGNING_KEY: &str = "let this device approve changes";
pub(crate) const EXECUTE_SHARED_ACT: &str = "carry out an approved change to the shared vault";
pub(crate) const FREE_TIME_POLICY: &str = "change how an agent uses its free time";
pub(crate) const HOME_PICK: &str = "change which device runs background organization";
pub(crate) const INFERENCE_DEFAULTS: &str = "change the default AI settings";
pub(crate) const JOIN_RESTORED_INSTALL: &str = "join this restored vault";
pub(crate) const KIT_ACTIVATION: &str = "activate a recovery kit";
pub(crate) const LEAVE_SHARED_VAULT: &str = "leave the shared vault";
pub(crate) const MODEL_PACK_REVERT: &str = "switch back to the earlier AI model pack";
pub(crate) const NAME_DEVICE_PREDECESSOR: &str = "name this device as the replacement for another";
pub(crate) const NON_BASE_WORLD_CLAIM_FRACTION: &str =
    "change how much context comes from other worlds";
pub(crate) const ORIGIN_CUT: &str = "change which host writes this repository";
pub(crate) const PROACTIVITY_POLICY: &str = "change how your digest is delivered";
pub(crate) const RECOVERY_PRESET: &str = "change how this vault can be recovered";
pub(crate) const RECOVER_OWNER_ROOT: &str = "restore your control of this vault";
pub(crate) const REMOVE_MACHINE: &str = "remove a device linked to this vault";
pub(crate) const REMOVE_OWNER_KEY: &str = "remove a device that can approve changes";
pub(crate) const REMOVE_SHARED_MEMBER: &str = "remove a member from the shared vault";
pub(crate) const ROOM_THREAD_ADMIN: &str = "change admin access to private conversations";
pub(crate) const SETTING_CHANGE: &str = "change a vault setting";
pub(crate) const SET_MACHINE_ROLE: &str = "change what a device may do in this vault";
pub(crate) const SHARED_TRAINING_SETUP: &str = "turn on learning from conversations";
pub(crate) const SIGN_OWNER_KEY_MOVE: &str = "approve removing a member's device keys";
pub(crate) const UNDO_SEND: &str = "change how long you can undo sending a message";
