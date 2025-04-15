use super::{Error, Settings, TokenVerifier};
use jwt_simple::algorithms::RS256PublicKey;
use std::future::Future;
use std::{collections::HashMap, time::Duration};
use tokio::sync::watch;

mod base64_serde;
mod jwk_set;

pub struct JwkCache {
    client: reqwest::Client,
    jwks: watch::Sender<HashMap<String, RS256PublicKey>>,
    url: String,
    cache_duration: Duration,
}

impl JwkCache {
    pub async fn new(settings: Settings) -> Result<(TokenVerifier, Self), Error> {
        let client = reqwest::Client::new();
        let url = settings.url.clone();
        let (jwks, max_age) = jwk_set::fetch_key_set(&client, &url).await?;
        let (sender, receiver) = watch::channel(jwks);
        let cache = Self {
            client,
            jwks: sender,
            url,
            cache_duration: max_age,
        };
        let verifier = TokenVerifier::new(receiver, settings)?;
        Ok((verifier, cache))
    }

    pub async fn run<F>(mut self, mut shutdown: F)
    where
        F: Future<Output = ()> + Send + Unpin + 'static,
    {
        tracing::info!("starting firebase auth id token jwk cache");

        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = tokio::time::sleep(self.cache_duration) => {
                    let new_cache_duration = self
                        .refresh_key_set()
                        .await
                        .inspect_err(|err| tracing::error!(?err, "failure to refresh firebase auth token verifying public keys"))
                        .unwrap_or(Duration::from_secs(60));
                    self.cache_duration = new_cache_duration
                }
            }
        }

        tracing::info!("stopping firebase auth id token jwk cache");
    }

    async fn refresh_key_set(&mut self) -> Result<Duration, Error> {
        let (new_jwks, new_max_age) = jwk_set::fetch_key_set(&self.client, &self.url).await?;
        self.jwks.send_replace(new_jwks);
        Ok(new_max_age)
    }
}
