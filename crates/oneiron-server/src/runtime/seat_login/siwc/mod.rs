//! Runtime-local Sign in with ChatGPT. Token-bearing records never enter
//! seat settings, a vault, or the official CLI environment.

mod credential;
mod identity;
mod login;
mod logout;
mod record;
mod refresh;

pub(crate) use credential::CredentialSource;
pub(crate) use login::{LoginOptions, login};
pub(crate) use logout::{RevokeOptions, SignOut, clear, revoke};

const ISSUER: &str = "https://auth.openai.com";
const JWKS_URI: &str = "https://auth.openai.com/.well-known/jwks.json";
const TOKEN_ENDPOINT: &str = "https://auth.openai.com/api/accounts/oauth/token";
const REVOCATION_ENDPOINT: &str = "https://auth.openai.com/api/accounts/oauth/revoke";
const DIRECT_SCOPE: &str = "chatgpt.tokens.use.direct";
