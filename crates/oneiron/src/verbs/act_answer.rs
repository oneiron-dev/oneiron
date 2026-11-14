//! What an act answers its caller (FIX 3414). The act runs as its caller's
//! authority asked, from whatever surface it asked; only the answer is judged
//! for where it goes. A caller off this device whose act's record, or a row
//! its reply would carry, stays on this device (DEC-0005) hears that the act
//! ran, and nothing of those rows. A connector's questions are the one
//! answer narrowed in part (FIX 5824): only the text of a question that
//! names such a row stays here, and the path to answer them leaves whole.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::act_answer::{
    ActAnswer, DetailsOnDevice, NarrowedQuestion, NarrowedQuestions,
};
