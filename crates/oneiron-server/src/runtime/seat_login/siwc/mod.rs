//! Runtime-local Sign in with ChatGPT. Token-bearing records never enter
//! seat settings, a vault, or the official CLI environment.

mod identity;
mod login;
mod record;

pub(crate) use login::{LoginOptions, login};

const ISSUER: &str = "https://auth.openai.com";
const JWKS_URI: &str = "https://auth.openai.com/.well-known/jwks.json";
const TOKEN_ENDPOINT: &str = "https://auth.openai.com/api/accounts/oauth/token";
const DIRECT_SCOPE: &str = "chatgpt.tokens.use.direct";
