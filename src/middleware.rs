use super::{ALG, FirebaseClaims, TOKEN_SIG_TYPE, TokenVerifier};
use axum::{
    Json,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use jwt_simple::{
    claims::{JWTClaims, NoCustomClaims},
    prelude::EdDSAPublicKeyLike,
    token::Token,
};
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct FirebaseAuthLayer {
    verifier: TokenVerifier,
}

impl FirebaseAuthLayer {
    pub fn new(verifier: TokenVerifier) -> Self {
        Self { verifier }
    }
}

impl<S> Layer<S> for FirebaseAuthLayer {
    type Service = FirebaseAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FirebaseAuthService {
            inner,
            verifier: self.verifier.clone(),
        }
    }
}

#[derive(Clone)]
pub struct FirebaseAuthService<S> {
    inner: S,
    verifier: TokenVerifier,
}

impl<S> FirebaseAuthService<S> {
    fn token_auth(&self, req: &mut Request) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| auth_value.strip_prefix("Bearer "))
            .ok_or_else(|| {
                metrics::counter!("firebase-token-auth-rejected", "reason" => "missing-token")
                    .increment(1);
                tracing::debug!("request missing required firebase auth token");
                error_response()
            })?;

        if let Some(ref bearer_verifier) = self.verifier.bearer_verifier {
            if let Ok(claims) = bearer_verifier.verify_token::<NoCustomClaims>(token, None) {
                let sub = if let Some(ref bearer) = claims.subject {
                    bearer
                } else {
                    "unknown"
                };
                tracing::info!(subject = %sub, "bearer request authorized");
                req.extensions_mut().insert(claims);
                return Ok(());
            }
        }

        let metadata = Token::decode_metadata(token).map_err(|_| {
            metrics::counter!("firebase-token-auth-rejected", "reason" => "missing-metadata")
                .increment(1);
            tracing::debug!(token, "token missing metadata");
            error_response()
        })?;

        // Check token header `alg` and `typ` field match the expected values
        if metadata.algorithm() != ALG || metadata.signature_type() != Some(TOKEN_SIG_TYPE) {
            metrics::counter!("firebase-token-auth-rejected", "reason" => "invalid-algorithm")
                .increment(1);
            tracing::debug!(
                alg = metadata.algorithm(),
                typ = metadata.signature_type(),
                "invalid token metadata headers",
            );
            return Err(error_response());
        }

        let Some(key_id) = metadata.key_id() else {
            metrics::counter!("firebase-token-auth-rejected", "reason" => "missing-kid")
                .increment(1);
            tracing::debug!("token missing kid metadata header");
            return Err(error_response());
        };

        // Validates the token signature and that the expiry (+tolerance) is within the limit
        // automatically. Also incorporates validation of issuer and audience (firebase project id)
        let claims: JWTClaims<FirebaseClaims> =
            self.verifier.verify_token(key_id, token).map_err(|_| {
                metrics::counter!("firebase-token-auth-rejected", "reason" => "invalid-token")
                    .increment(1);
                tracing::debug!(token, key_id, "invalid firebase auth id token");
                error_response()
            })?;

        metrics::counter!("firebase-request-authorized").increment(1);
        req.extensions_mut().insert(claims);

        Ok(())
    }
}

impl<S> Service<Request> for FirebaseAuthService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(ctx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);
        let auth_result = self.token_auth(&mut req);

        Box::pin(async move {
            match auth_result {
                Ok(_) => ready_inner.call(req).await,
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

fn error_response() -> (StatusCode, Json<serde_json::Value>) {
    let err_resp = serde_json::json!({
        "status": "error",
        "message": "request not authorized",
    });
    (StatusCode::UNAUTHORIZED, Json(err_resp))
}
