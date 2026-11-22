//! Signing helpers for tests that build JWS documents.
//!
//! The crate signs nothing outside this module, which exists only with the
//! `auth` and `test-util` features both on. Keys come from a fixed seed, so
//! the same seed always gives the same key; there is no random key.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};

use super::{Jwk, PublicKey, Typ, b64};

/// An Ed25519 signing key for tests, made from a 32-byte seed.
pub struct TestKey {
    signing_key: SigningKey,
}

impl TestKey {
    /// Makes the key for `seed`; the same seed always makes the same key.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_verifying_key(self.signing_key.verifying_key())
    }

    /// Returns the 32 raw bytes of the public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the public key as a JWK.
    #[must_use]
    pub fn jwk(&self) -> Jwk {
        Jwk::from(self.public_key())
    }

    /// Signs `payload` as a compact JWS with the header
    /// `{"alg":"EdDSA","typ":<typ>,"kid":<kid>}`.
    #[must_use]
    pub fn sign(&self, typ: Typ, kid: &str, payload: &[u8]) -> String {
        let header = format!(
            r#"{{"alg":"EdDSA","typ":{},"kid":{}}}"#,
            json_string(typ.as_str()),
            json_string(kid),
        );
        self.sign_raw(header.as_bytes(), payload)
    }

    /// Signs a compact JWS made of `header` and `payload` exactly as given,
    /// whatever they hold, for building documents that must be rejected.
    #[must_use]
    pub fn sign_raw(&self, header: &[u8], payload: &[u8]) -> String {
        let signing_input = format!("{}.{}", b64::encode(header), b64::encode(payload));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64::encode(&signature.to_bytes()))
    }
}

impl fmt::Debug for TestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).expect("serializing a string to JSON cannot fail")
}
