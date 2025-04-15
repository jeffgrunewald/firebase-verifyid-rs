use crate::{Error, GOOGLE_PUBKEY_URI};
use jwt_simple::{
    common::VerificationOptions,
    prelude::{Duration, Ed25519PublicKey},
};
use serde::Deserialize;
use std::{collections::HashSet, fs};

#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    /// The URL to retrieve rotating jwks from Firebase
    #[serde(default = "default_jwk_url")]
    pub url: String,
    /// Firebase project number
    pub project_id: String,
    /// The maximum amount of time in seconds after a token has expired to allow a token to verify
    pub max_validity_secs: Option<u64>,
    /// How much clock in seconds to tolerate when verifying token timestamps; default 15 min
    pub time_tolerance_secs: Option<u64>,
    /// Accepts tokens in the future
    pub accept_future: Option<bool>,
    /// Bypass Firebase Token with self-issued JWT bearer tokens
    /// The base58-encoded address of, or the path to, the PEM-encoded Ed2559 public signing key
    pub bearer_pubkey: Option<String>,
}

fn default_jwk_url() -> String {
    GOOGLE_PUBKEY_URI.to_string()
}

impl Settings {
    pub fn max_validity(&self) -> Option<Duration> {
        self.max_validity_secs.map(Duration::from_secs)
    }

    pub fn time_tolerance(&self) -> Option<Duration> {
        self.time_tolerance_secs.map(Duration::from_secs)
    }

    pub fn bearer_pubkey(&self) -> Option<Result<Ed25519PublicKey, Error>> {
        self.bearer_pubkey.as_ref().map(|addr_or_path| {
            bs58::decode(&addr_or_path)
                .into_vec()
                .map_err(|err| err.into())
                .and_then(|bytes| Ed25519PublicKey::from_bytes(&bytes))
                .or_else(|_| {
                    fs::read_to_string(addr_or_path)
                        .map_err(|err| err.into())
                        .and_then(|pem| Ed25519PublicKey::from_pem(&pem).map_err(|err| err.into()))
                })
        })
    }
}

impl From<Settings> for VerificationOptions {
    fn from(settings: Settings) -> Self {
        let default = VerificationOptions::default();
        VerificationOptions {
            accept_future: settings.accept_future.unwrap_or(default.accept_future),
            allowed_issuers: Some(HashSet::from([format!(
                "https://securetoken.google.com/{}",
                settings.project_id
            )])),
            allowed_audiences: Some(HashSet::from([settings.project_id.clone()])),
            time_tolerance: settings.time_tolerance().or(default.time_tolerance),
            max_validity: settings.max_validity().or(default.max_validity),
            ..default
        }
    }
}
