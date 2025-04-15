mod jwk_cache;
pub mod middleware;
mod settings;
mod token_verifier;

pub use jwk_cache::JwkCache;
pub use settings::Settings;
pub use token_verifier::TokenVerifier;

pub use jwt_simple::claims;

pub const KTY: &str = "RSA";
pub const ALG: &str = "RS256";
pub const TOKEN_SIG_TYPE: &str = "JWT";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct FirebaseClaims {
    pub email_verified: bool,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub user_id: String,
    pub auth_time: u64,
    pub firebase: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("jwt token or pubkey error {0}")]
    JwtError(#[from] jwt_simple::Error),
    #[error("unauthorized bearer token {0}")]
    UnknownBearer(String),
    #[error("failed to fetch jwks {0}")]
    JwkRefresh(#[from] reqwest::Error),
    #[error("no compatible keys in set {0}")]
    JwkSetEmpty(String),
    #[error("token kid does not match known key {0}")]
    UnknownJwk(String),
    #[error("error reading jwk pem from file {0}")]
    PemReadFile(#[from] std::io::Error),
}

pub(crate) const GOOGLE_PUBKEY_URI: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

#[cfg(test)]
mod test {
    use jwt_simple::reexports::ct_codecs::{Base64UrlSafeNoPadding, Decoder};

    use super::*;

    #[test]
    fn decode_claims() {
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJodHRwczovL2lkZW50aXR5dG9vbGtpdC5nb29nbGUuY29tL2ZpcmViYXNlLXByb2plY3QtaWQiLCJhdWQiOiJmaXJlYmFzZS1wcm9qZWN0LWlkIiwiaWF0IjoxNzEwMTMyMDAwLCJleHAiOjE3MTAxMzU2MDAsInVzZXJfaWQiOiJ1c2VyX2lkX2V4YW1wbGUiLCJzdWIiOiJ1c2VyX2lkX2V4YW1wbGUiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzX2F1dGgiOiJjdXN0b21Ub2tlbkF1dGgiLCJhdXRoX3RpbWUiOjE3MTAxMzIwMDAsImZpcmViYXNlIjp7InNpZ25faW5wcm92ZWQiOnRydWUsImxvZ2luX3Byb3ZpZGVyIjoiY29udGFjdHNwYWNlIiwidXNlcl9zdGF0dXMiOiJhY3RpdmUifX0.SGVsbG9UaGVyZVNob3VsZGJFUmVhbFNpZ25hdHVyZUJ1dEl0cydNb2NrZWQ";
        let claims_component = token.split(".").collect::<Vec<_>>()[1];
        let decoded_token: FirebaseClaims = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(claims_component, None).expect("valid token"),
        )
        .expect("valid decode struct");
        println!("{decoded_token:?}");
    }
}
