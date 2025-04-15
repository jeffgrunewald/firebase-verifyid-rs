use super::{Error, HashMap, RS256PublicKey, base64_serde::deserialize};
use crate::{ALG, KTY};
use reqwest::{Response, header::CACHE_CONTROL};
use serde::Deserialize;
use std::time::Duration;

pub(super) async fn fetch_key_set(
    client: &reqwest::Client,
    url: &str,
) -> Result<(HashMap<String, RS256PublicKey>, Duration), Error> {
    let response = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .inspect_err(|err| {
            tracing::warn!(?err, "failed to retrieve jwk set");
        })?;

    let max_age = Duration::from_secs(parse_max_age(&response));
    let jwk_set = response
        .json::<JwkSet>()
        .await?
        .keys
        .into_iter()
        .filter(|key| key.alg == ALG && key.kty == KTY)
        .try_fold(HashMap::new(), |mut set, key| {
            let pub_key = RS256PublicKey::from_components(&key.n, &key.e).map_err(Error::from)?;
            tracing::info!(key_id = %key.kid, "adding public key to validation cache");
            set.insert(key.kid, pub_key);
            Ok::<_, jwt_simple::Error>(set)
        })?;
    Ok((jwk_set, max_age))
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    alg: String,
    kid: String,
    #[serde(deserialize_with = "deserialize")]
    n: Vec<u8>,
    #[serde(deserialize_with = "deserialize")]
    e: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

fn parse_max_age(resp: &Response) -> u64 {
    resp.headers()
        .get(CACHE_CONTROL)
        .and_then(|cache_control| {
            cache_control.to_str().ok().map(|header| {
                let mut parsed_max_age = header
                    .split(",")
                    .filter(|item| item.to_lowercase().contains("max-age"))
                    .flat_map(|item| item.trim().split("=").collect::<Vec<_>>())
                    .map(|item| item.parse::<u64>())
                    .filter(|item| item.is_ok())
                    .collect::<Vec<_>>();

                parsed_max_age.pop().transpose().ok().flatten()
            })
        })
        .flatten()
        .unwrap_or(60)
}
