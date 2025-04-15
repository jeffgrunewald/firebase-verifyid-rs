# Dead-simple Firebase auth id JWT token validation for Rust servers

## What

An opinionated and very purposeful implementation of a Firebase auth id token validator for
performing token validation by Rust backend services. Assumes the implementing service utilizes
the Tokio runtime for long-running Rust server apps, some form of shutdown signaling functionality
like a tokio CancellationToken or Triggered::Listener to monitor for shutdown signals from the
parent application, the Tracing crate for logging events from the caching task and Axum for the backend API.

## Why

Other implementations of the Firebase Admin SDK that solve this problem are swiss army knives
that contain every attachment, including the kitchen sink and require Firebase account credentials
to be loaded into your token-validating app. This is unnecessary tossing around of credentials
when the validating RS256 public keys to validate the tokens are publicly available from Firebase
without needing to authenticate. I just want to construct some pubkeys from components and
validate a token's signature/stuff its claims into my Axum extension in a middleware, is that
too much to ask?

## How

The Firebase Verifier ID backend Rust crate has three primary components:
* A `TokenVerifier` which contains the cached collection of `RS256PublicKey`s indexed by
  `kid` within a HashMap that performs individual request token validation by verifying
  the supplied key against the project number and standard JWT claims and of course, the token signature.
  Successfully validated tokens have their custom Firebase claims injected into the Axum request
  Extension for later extraction downstream in the Axum handlers.

* A `JwkCache` which runs as a persistent background task, spawned on the Tokio runtime and
  listening for shutdown signals from the parent application, meanwhile refreshing the cache
  of public keys used to perform token validation determined by the Cache-Control value from the
  previous request.

* A `FirebaseAuthLayer` Axum middleware layer for injecting the check into the application router.

The `settings.rs` module provides the configuration knobs for customizing the behavior of the crate.
The only required configuration value is the Firebase Project ID for configuring the `iss` and `aud`
values of the auth token. Other config values of note are the duration the cache task should wait
before refreshing the public keys and timing fields for validating the token is unexpired within
tolerances and boundaries.
