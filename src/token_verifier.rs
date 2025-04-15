use super::{Error, FirebaseClaims, Settings};
use jwt_simple::{
    algorithms::{RS256PublicKey, RSAPublicKeyLike},
    claims::JWTClaims,
    common::VerificationOptions,
    prelude::Ed25519PublicKey,
};
use std::collections::HashMap;
use tokio::sync::watch;

#[derive(Clone)]
pub struct TokenVerifier {
    jwks: watch::Receiver<HashMap<String, RS256PublicKey>>,
    verify_opts: VerificationOptions,
    pub(crate) bearer_verifier: Option<Ed25519PublicKey>,
}

impl TokenVerifier {
    pub fn new(
        jwks: watch::Receiver<HashMap<String, RS256PublicKey>>,
        settings: Settings,
    ) -> Result<Self, Error> {
        let bearer_verifier = settings.bearer_pubkey().transpose()?;
        Ok(Self {
            jwks,
            verify_opts: settings.into(),
            bearer_verifier,
        })
    }

    pub fn verify_token(
        &self,
        key_id: &str,
        token: &str,
    ) -> Result<JWTClaims<FirebaseClaims>, Error> {
        self.jwks
            .borrow()
            .get(key_id)
            .map(|pubkey| {
                pubkey.verify_token::<FirebaseClaims>(token, Some(self.verify_opts.clone()))
            })
            .ok_or_else(|| Error::UnknownJwk(key_id.to_string()))?
            .map_err(Error::from)
    }
}
